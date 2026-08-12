// ZygoteNextProbe native service probe (C++).
// Runs inside a native isolated process forked by zygote_next (LOS/AOSP 17).
// Key question: does this process live in init's GLOBAL mount namespace?
//
// All Android APIs that need ART are unavailable here; we only use libc plus
// dlsym()ed log/binder calls, so everything is self-contained.
//
// Bind flow: the Kotlin app binds an android:nativeService=true isolated
// service. AMS routes the spawn to zygote_next, which loads libmain.so from
// the APK and calls ANativeService_onCreate. We then register an onBind
// callback returning a real AIBinder (libbinder_ndk, dlsym'd) that answers
// the AIDL methods (getResult=1, getCapabilities=2) so the UI can display
// the report.

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "ZygoteNextProbe"
#define STATUS_OK 0

typedef void* (*dlopen_fn)(const char*, int);
typedef void* (*dlsym_fn)(void*, const char*);
typedef void (*log_print_fn)(int, const char*, const char*, ...);

static log_print_fn g_log_print = NULL;
static char g_report[8192];
static char g_caps[2048];

static void logmsg(const char* fmt, ...) {
    if (!g_log_print) return;
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log_print(6 /* ANDROID_LOG_INFO */, LOG_TAG, "%s", buf);
}

static int read_file(const char* path, char* out, size_t out_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, out_size - 1);
    close(fd);
    if (n < 0) return -1;
    out[n] = '\0';
    return 0;
}

static uint64_t read_ns_inode(const char* path) {
    char buf[256];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char* open_bracket = strrchr(buf, '[');
    if (!open_bracket) return 0;
    return strtoull(open_bracket + 1, NULL, 10);
}

// Propagation of the root mount: shared:N vs master:N.
static int root_propagation(char* out, size_t out_size) {
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char* newline = strchr(buf, '\n');
    if (newline) *newline = '\0';
    char* line = buf;
    // fields: id parent major:minor root mountpoint options [shared/master:X]...
    // find the last field before the separator that starts with shared:/master:
    char* start = NULL;
    char* p = line;
    while (p && *p) {
        if (strncmp(p, "shared:", 7) == 0 || strncmp(p, "master:", 7) == 0) {
            start = p;
        }
        p = strchr(p, ' ');
        if (p) p++;
    }
    if (!start) {
        snprintf(out, out_size, "(none)");
        return 0;
    }
    char* end = strchr(start, ' ');
    size_t len = end ? (size_t)(end - start) : strlen(start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static uint64_t hash_mountinfo(const char* path) {
    // simple FNV-1a 64 over the file; "fingerprint" comparison only
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[8192];
    uint64_t h = 1469598103934665603ULL;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            h ^= (unsigned char)buf[i];
            h *= 1099511628211ULL;
        }
    }
    close(fd);
    return h;
}

static char* read_groups(char* out, size_t out_size) {
    char buf[2048];
    if (read_file("/proc/self/status", buf, sizeof(buf)) < 0) {
        snprintf(out, out_size, "(unreadable)");
        return out;
    }
    char* line = strstr(buf, "Groups:");
    if (!line) {
        snprintf(out, out_size, "(missing)");
        return out;
    }
    line += 7;
    while (*line == '\t' || *line == ' ') line++;
    char* end = strchr(line, '\n');
    if (end) *end = '\0';
    snprintf(out, out_size, "%s", line);
    return out;
}

static char* read_cmdline(char* out, size_t out_size) {
    if (read_file("/proc/self/cmdline", out, out_size) < 0) {
        snprintf(out, out_size, "(unreadable)");
        return out;
    }
    for (char* c = out; c < out + strlen(out); c++) {
        if (*c == '\0') *c = ' ';
    }
    return out;
}

static int proc1_readable(void) {
    int fd = open("/proc/1/comm", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int find_zygote_next(void) {
    // best effort: scan /proc/<pid>/comm for "zygote_next"
    char path[64];
    for (int i = 0; i < 65536; i++) {
        snprintf(path, sizeof(path), "/proc/%d/comm", i);
        char comm[64];
        if (read_file(path, comm, sizeof(comm)) == 0) {
            if (strstr(comm, "zygote_next")) return 1;
        }
    }
    return 0;
}

static void scan_root_markers(char* out, size_t out_size) {
    out[0] = '\0';
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    char* save;
    char* line = strtok_r(buf, "\n", &save);
    while (line) {
        if (strstr(line, "magisk") || strstr(line, "ksu") || strstr(line, "KSU")
            || strstr(line, "/debug_ramdisk") || strstr(line, "/adb/")) {
            if (out[0] != '\0') strncat(out, ", ", out_size - strlen(out) - 1);
            strncat(out, line, out_size - strlen(out) - 1);
        }
        line = strtok_r(NULL, "\n", &save);
    }
}

static void build_caps(void) {
    char groups[512];
    read_groups(groups, sizeof(groups));

    // proc mount options from /proc/self/mountinfo (hidepid etc.)
    char proc_opts[128] = "";
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[8192];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            char* save;
            char* line = strtok_r(buf, "\n", &save);
            while (line) {
                char* sep = strstr(line, " - ");
                if (sep) {
                    char* rest = sep + 3;
                    char* type_end = strchr(rest, ' ');
                    if (type_end && strncmp(rest, "proc", 4) == 0) {
                        // options are field 5 (before " - ")
                        char* pre = line;
                        char* f1 = strchr(pre, ' ');
                        char* f2 = f1 ? strchr(f1 + 1, ' ') : NULL;
                        char* f3 = f2 ? strchr(f2 + 1, ' ') : NULL;
                        char* f4 = f3 ? strchr(f3 + 1, ' ') : NULL;
                        char* f5 = f4 ? strchr(f4 + 1, ' ') : NULL;
                        char* f5end = f5 ? strchr(f5 + 1, ' ') : NULL;
                        if (f5 && f5end) {
                            size_t len = (size_t)(f5end - f5 - 1);
                            if (len >= sizeof(proc_opts)) len = sizeof(proc_opts) - 1;
                            memcpy(proc_opts, f5 + 1, len);
                            proc_opts[len] = '\0';
                        }
                    }
                }
                line = strtok_r(NULL, "\n", &save);
            }
        }
    }

    // PID visibility: count /proc entries, attempt /proc/<pid>/status reads
    int total = 0, unreadable = 0;
    for (int i = 0; i < 65536; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", i);
        if (access(path, F_OK) == 0) {
            total++;
            char buf[8];
            if (read_file(path, buf, sizeof(buf)) < 0) unreadable++;
        }
    }

    snprintf(g_caps, sizeof(g_caps),
             "groups: %s\n"
             "uid: %d (isolated)\n"
             "proc mount: %s\n"
             "pids total: %d\n"
             "pids unreadable: %d\n"
             "AID_READPROC 3009: %s\n",
             groups, getuid(), proc_opts[0] ? proc_opts : "(none)", total, unreadable,
             strstr(groups, "3009") ? "inherited (leak)" : "not present");
}

static void run_probe(void) {
    pid_t pid = getpid();
    pid_t ppid = getppid();
    uid_t uid = getuid();
    gid_t gid = getgid();

    uint64_t self_ns = read_ns_inode("/proc/self/ns/mnt");
    uint64_t init_ns = read_ns_inode("/proc/1/ns/mnt");

    char prop[64];
    root_propagation(prop, sizeof(prop));
    bool global_view = strncmp(prop, "shared:", 7) == 0;
    bool private_view = strncmp(prop, "master:", 7) == 0;

    char groups[512];
    read_groups(groups, sizeof(groups));
    bool leak_3009 = strstr(groups, "3009") != NULL;

    char cmdline[256];
    read_cmdline(cmdline, sizeof(cmdline));

    char self_fp[32];
    uint64_t self_fpv = hash_mountinfo("/proc/self/mountinfo");
    snprintf(self_fp, sizeof(self_fp), "%016" PRIx64, self_fpv);

    char markers[512];
    scan_root_markers(markers, sizeof(markers));

    int p1_readable = proc1_readable();
    int zn_found = find_zygote_next();

    // Machine format consumed by ProbeResult.parse() (11 pipe-separated fields):
    // pid|isolated|mntNsSelf|mntNsInit|proc1Readable|mntNsZygoteNext|zygoteNext|
    // selfFingerprint|selfPropagation|zygoteNextProps|rootMarkers
    snprintf(g_report, sizeof(g_report),
             "%d|true|%" PRIu64 "|%" PRIu64 "|%s|0|%s|%s|%s||%s", pid, self_ns, init_ns,
             p1_readable ? "true" : "false", zn_found ? "true" : "false", self_fp, prop, markers);

    logmsg("=== NATIVE SERVICE PROBE (pid=%d ppid=%d uid=%d gid=%d) ===", pid, ppid, uid, gid);
    logmsg("mnt ns self = %" PRIu64 " init = %" PRIu64 " (init unreadable under isolated uid)", self_ns,
           init_ns);
    logmsg("root mount propagation = %s (%s)", prop,
           global_view ? "shared: GLOBAL ns (zygote_next)"
                       : private_view ? "master: private ns (classic zygote)" : "unclassifiable");
    logmsg("mountinfo fp self = %s", self_fp);
    logmsg("groups = %s (AID_READPROC/3009 inherited: %s)", groups, leak_3009 ? "YES" : "no");
    logmsg("cmdline = %s", cmdline);
    logmsg("toLine = %s", g_report);
}

// ---- libbinder_ndk (dlsym'd; NDK 29 ships headers but no stub lib) ----

typedef struct AIBinder_Class AIBinder_Class;
typedef struct AIBinder AIBinder;
typedef struct AParcel AParcel;

typedef void (*aibinder_class_oncreate_fn)(void* args);
typedef void (*aibinder_class_ondestroy_fn)(void* args);
typedef int (*aibinder_class_ontransact_fn)(AIBinder* binder, uint32_t code, const AParcel* in,
                                            AParcel* out);
typedef AIBinder_Class* (*aibinder_class_define_fn)(const char* descriptor,
                                                    aibinder_class_oncreate_fn onCreate,
                                                    aibinder_class_ondestroy_fn onDestroy,
                                                    aibinder_class_ontransact_fn onTransact);
typedef AIBinder* (*aibinder_new_fn)(const AIBinder_Class* clazz, void* args);
typedef int (*aparcel_write_string_fn)(AParcel* parcel, const char* string, uint32_t length);
typedef int (*aparcel_write_int32_fn)(AParcel* parcel, int32_t value);

static aibinder_class_define_fn g_class_define;
static aibinder_new_fn g_aibinder_new;
static aparcel_write_string_fn g_parcel_write_string;
static aparcel_write_int32_fn g_parcel_write_int32;
static const AIBinder_Class* g_probe_class;

static void probe_class_create(void* args) {
    (void)args;
}

static void probe_class_destroy(void* args) {
    (void)args;
}

static int probe_transact(AIBinder* binder, uint32_t code, const AParcel* in, AParcel* out) {
    (void)binder;
    (void)in;
    logmsg("onTransact code=%u", code);
    // AIDL methods (transaction codes start at 1 = FIRST_CALL_TRANSACTION):
    // 1 = getResult(), 2 = getCapabilities(). Both return String.
    // Reply layout: int32 exceptionCode(NO_EXCEPTION=0) + String
    if ((code == 1 || code == 2) && g_parcel_write_string && g_parcel_write_int32) {
        int rc = g_parcel_write_int32(out, STATUS_OK);
        if (rc != STATUS_OK) return -22;
        const char* payload = code == 1 ? g_report : g_caps;
        rc = g_parcel_write_string(out, payload, (uint32_t)strlen(payload));
        logmsg("onTransact code=%u wrote %zu bytes rc=%d", code, strlen(payload), rc);
        return rc == STATUS_OK ? STATUS_OK : -22 /* STATUS_BAD_TYPE-ish */;
    }
    return -2; // STATUS_UNKNOWN_TRANSACTION-ish
}

static void resolve_binder_ndk(void) {
    void* dl = dlopen("libbinder_ndk.so", RTLD_NOW);
    if (!dl) {
        logmsg("libbinder_ndk.so dlopen failed: %s", dlerror());
        return;
    }
    g_class_define = (aibinder_class_define_fn)dlsym(dl, "AIBinder_Class_define");
    g_aibinder_new = (aibinder_new_fn)dlsym(dl, "AIBinder_new");
    g_parcel_write_string = (aparcel_write_string_fn)dlsym(dl, "AParcel_writeString");
    g_parcel_write_int32 = (aparcel_write_int32_fn)dlsym(dl, "AParcel_writeInt32");
    logmsg("binder_ndk: define=%p new=%p write=%p w32=%p", (void*)g_class_define,
           (void*)g_aibinder_new, (void*)g_parcel_write_string, (void*)g_parcel_write_int32);
    if (g_class_define) {
        g_probe_class = g_class_define("io.github.xiaotong6666.zygotenextprobe.IZygoteNextProbeService",
                                       probe_class_create, probe_class_destroy, probe_transact);
        logmsg("probe class defined: %p", (const void*)g_probe_class);
    }
}

// onBind callback: return a real AIBinder so the Java client gets
// onServiceConnected and can call getResult() to read the report.
static AIBinder* probe_onbind(void* service, uint64_t token, const char* action, const char* data) {
    (void)service;
    (void)token;
    (void)action;
    (void)data;
    logmsg("onBind called");
    if (g_aibinder_new && g_probe_class) {
        AIBinder* b = g_aibinder_new(g_probe_class, NULL);
        logmsg("onBind -> AIBinder %p", (void*)b);
        return b;
    }
    logmsg("onBind -> NULL (binder_ndk not resolved)");
    return NULL;
}

extern "C" __attribute__((visibility("default"))) void ANativeService_onCreate(void* service) {
    // Resolve runtime symbols manually (NDK 29 lacks API-37 headers for this).
    void* dl = dlopen("liblog.so", RTLD_NOW);
    if (dl) {
        g_log_print = (log_print_fn)dlsym(dl, "__android_log_print");
    }
    resolve_binder_ndk();
    build_caps();
    run_probe();

    void* binder_dl = dlopen("libandroid.so", RTLD_NOW);
    if (binder_dl) {
        void* set_bind = dlsym(binder_dl, "ANativeService_setOnBindCallback");
        if (set_bind) {
            // ANativeService_setOnBindCallback(service, callback)
            ((void (*)(void*, void*))set_bind)(service, (void*)&probe_onbind);
        }
    }
}
