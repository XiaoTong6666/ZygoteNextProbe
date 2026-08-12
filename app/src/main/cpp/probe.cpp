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
// the AIDL method getResult (code 1) so the UI can display the report.

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
    if (out_size == 0) return -1;
    out[0] = '\0';
    FILE* file = fopen("/proc/self/mountinfo", "r");
    if (!file) return -1;

    char* line = NULL;
    size_t line_size = 0;
    int result = -1;
    while (getline(&line, &line_size, file) >= 0) {
        char* separator = strstr(line, " - ");
        if (!separator) continue;
        *separator = '\0';

        bool root_mount = false;
        int field = 1;
        char* save = NULL;
        for (char* token = strtok_r(line, " ", &save); token;
             token = strtok_r(NULL, " ", &save), field++) {
            if (field == 5) {
                root_mount = strcmp(token, "/") == 0;
            } else if (root_mount && field >= 7
                       && (strncmp(token, "shared:", 7) == 0
                           || strncmp(token, "master:", 7) == 0)) {
                size_t used = strlen(out);
                if (used != 0 && used + 1 < out_size) {
                    out[used++] = ' ';
                    out[used] = '\0';
                }
                if (used < out_size - 1) {
                    strncat(out, token, out_size - used - 1);
                }
            }
        }

        if (root_mount) {
            if (out[0] == '\0') snprintf(out, out_size, "(none)");
            result = 0;
            break;
        }
    }
    free(line);
    fclose(file);
    return result;
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

// Read the whole file. mountinfo can exceed a fixed buffer on modern devices
// (150+ mounts, >16KB); also note procfs files report st_size == 0, so the
// buffer must grow dynamically instead of trusting fstat().
static char* read_all(const char* path, size_t* out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 65536;
    char* data = (char*)malloc(cap);
    if (!data) {
        close(fd);
        return NULL;
    }
    size_t total = 0;
    for (;;) {
        if (total + 16384 >= cap) {
            cap *= 2;
            char* bigger = (char*)realloc(data, cap);
            if (!bigger) {
                free(data);
                close(fd);
                return NULL;
            }
            data = bigger;
        }
        ssize_t n = read(fd, data + total, cap - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    data[total] = '\0';
    if (out_len) *out_len = total;
    return data;
}

static bool contains_ignore_case(const char* text, const char* needle) {
    if (!*needle) return true;
    for (; *text; text++) {
        const char* h = text;
        const char* n = needle;
        while (*h && *n
               && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++;
            n++;
        }
        if (!*n) return true;
    }
    return false;
}

static bool contains_named_marker(const char* text, const char* needle, bool require_end) {
    for (const char* start = text; *start; start++) {
        const char* h = start;
        const char* n = needle;
        while (*h && *n
               && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++;
            n++;
        }
        if (!*n) {
            bool start_boundary = start == text || !isalnum((unsigned char)start[-1]);
            bool end_boundary = !require_end || !*h || !isalnum((unsigned char)*h);
            if (start_boundary && end_boundary) return true;
        }
    }
    return false;
}

static void append_marker_label(char* labels, size_t labels_size, const char* label) {
    size_t used = strlen(labels);
    if (used != 0 && used + 1 < labels_size) {
        labels[used++] = '+';
        labels[used] = '\0';
    }
    if (used < labels_size - 1) strncat(labels, label, labels_size - used - 1);
}

// Root probe: report the matching label plus mountpoint, mount root and source.
static void scan_root_markers(char* out, size_t out_size) {
    out[0] = '\0';
    size_t len = 0;
    char* buf = read_all("/proc/self/mountinfo", &len);
    if (!buf) return;
    char* save;
    char* line = strtok_r(buf, "\n", &save);
    while (line) {
        bool marker_zn = contains_named_marker(line, "zn", true);
        bool marker_zygisk = contains_ignore_case(line, "zygisk");
        bool marker_sui = contains_named_marker(line, "sui", true);
        bool marker_ksu = contains_ignore_case(line, "kernelsu")
                          || contains_named_marker(line, "ksu", true);
        bool marker_lsp = contains_named_marker(line, "lsp", false);
        bool marker_magisk = contains_ignore_case(line, "magisk");
        bool marker_adb = contains_ignore_case(line, "/adb/");
        bool marker_debug_ramdisk = contains_ignore_case(line, "/debug_ramdisk");
        if (marker_zn || marker_zygisk || marker_sui || marker_ksu || marker_lsp
            || marker_magisk || marker_adb || marker_debug_ramdisk) {
            char labels[96] = "";
            if (marker_zn) append_marker_label(labels, sizeof(labels), "ZN");
            if (marker_zygisk) append_marker_label(labels, sizeof(labels), "Zygisk");
            if (marker_sui) append_marker_label(labels, sizeof(labels), "Sui");
            if (marker_ksu) append_marker_label(labels, sizeof(labels), "KernelSU");
            if (marker_lsp) append_marker_label(labels, sizeof(labels), "LSP");
            if (marker_magisk) append_marker_label(labels, sizeof(labels), "Magisk");
            if (marker_adb) append_marker_label(labels, sizeof(labels), "ADB");
            if (marker_debug_ramdisk) {
                append_marker_label(labels, sizeof(labels), "debug_ramdisk");
            }

            char root[192] = "?";
            char point[128] = "?";
            char type[64] = "?";
            char source[192] = "?";
            char* sep = strstr(line, " - ");
            if (sep) {
                // fields 4 and 5 = mount root and mountpoint
                char* p = line;
                char* f4 = NULL;
                char* f5 = NULL;
                for (int i = 0; i < 5; i++) {
                    char* sp = strchr(p, ' ');
                    if (!sp) break;
                    if (i == 3) f4 = p;
                    if (i == 4) f5 = p;
                    p = sp + 1;
                }
                if (f4) {
                    char* e = strchr(f4, ' ');
                    size_t rl = e ? (size_t)(e - f4) : strlen(f4);
                    if (rl >= sizeof(root)) rl = sizeof(root) - 1;
                    memcpy(root, f4, rl);
                    root[rl] = '\0';
                }
                if (f5) {
                    char* e = strchr(f5, ' ');
                    size_t pl = e ? (size_t)(e - f5) : strlen(f5);
                    if (pl >= sizeof(point)) pl = sizeof(point) - 1;
                    memcpy(point, f5, pl);
                    point[pl] = '\0';
                }
                // type after " - "
                char* rest = sep + 3;
                char* te = strchr(rest, ' ');
                size_t tl = te ? (size_t)(te - rest) : strlen(rest);
                if (tl >= sizeof(type)) tl = sizeof(type) - 1;
                memcpy(type, rest, tl);
                type[tl] = '\0';
                if (te) {
                    char* source_start = te + 1;
                    char* source_end = strchr(source_start, ' ');
                    size_t sl = source_end ? (size_t)(source_end - source_start)
                                           : strlen(source_start);
                    if (sl >= sizeof(source)) sl = sizeof(source) - 1;
                    memcpy(source, source_start, sl);
                    source[sl] = '\0';
                }
            }
            char entry[768];
            snprintf(entry, sizeof(entry), "%s: %s [%s; root=%s; source=%s]",
                     labels, point, type, root, source);
            if (out[0] != '\0') strncat(out, ", ", out_size - strlen(out) - 1);
            strncat(out, entry, out_size - strlen(out) - 1);
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(buf);
}

// Log the FULL mount view of this process to logcat, one line per record.
// The native isolated service cannot read /proc/1/mountinfo under its isolated
// uid, so dump its own complete view. Namespace equality can be cross-checked
// externally with a privileged shell when needed.
static void log_mountinfo_full(void) {
    size_t len = 0;
    char* buf = read_all("/proc/self/mountinfo", &len);
    if (!buf) return;
    logmsg("===== FULL MOUNT VIEW (native isolated process) %zu bytes =====", len);
    char* save;
    char* line = strtok_r(buf, "\n", &save);
    int idx = 0;
    while (line) {
        logmsg("[%03d] %s", idx++, line);
        line = strtok_r(NULL, "\n", &save);
    }
    free(buf);
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

    char cmdline[256];
    read_cmdline(cmdline, sizeof(cmdline));

    char markers[4096];
    scan_root_markers(markers, sizeof(markers));

    int p1_readable = proc1_readable();
    int zn_found = find_zygote_next();

    // Machine format consumed by ProbeResult.parse() (10 pipe-separated fields):
    // pid|isolated|mntNsSelf|mntNsInit|proc1Readable|mntNsZygoteNext|zygoteNext|
    // selfPropagation|zygoteNextProps|rootMarkers
    snprintf(g_report, sizeof(g_report),
             "%d|true|%" PRIu64 "|%" PRIu64 "|%s|0|%s|%s||%s", pid, self_ns, init_ns,
             p1_readable ? "true" : "false", zn_found ? "true" : "false", prop, markers);

    logmsg("=== NATIVE SERVICE PROBE (pid=%d ppid=%d uid=%d gid=%d) ===", pid, ppid, uid, gid);
    logmsg("mnt ns self = %" PRIu64 " init = %" PRIu64 " (init unreadable under isolated uid)", self_ns,
           init_ns);
    logmsg("root mount propagation = %s (%s)", prop,
            global_view ? "shared propagation (zygote_next global-view signature)"
                        : private_view ? "master: private ns (classic zygote)" : "unclassifiable");
    logmsg("root markers = %s", markers);
    logmsg("cmdline = %s", cmdline);
    logmsg("toLine = %s", g_report);
    log_mountinfo_full();
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
    // AIDL method (transaction code 1 = FIRST_CALL_TRANSACTION): getResult().
    // Reply layout: int32 exceptionCode(NO_EXCEPTION=0) + String
    if (code == 1 && g_parcel_write_string && g_parcel_write_int32) {
        int rc = g_parcel_write_int32(out, STATUS_OK);
        if (rc != STATUS_OK) return -22;
        rc = g_parcel_write_string(out, g_report, (uint32_t)strlen(g_report));
        logmsg("onTransact code=%u wrote %zu bytes rc=%d", code, strlen(g_report), rc);
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
