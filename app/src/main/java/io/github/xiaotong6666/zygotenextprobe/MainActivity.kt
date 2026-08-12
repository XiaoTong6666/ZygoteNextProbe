package io.github.xiaotong6666.zygotenextprobe

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.RemoteException
import android.util.Log
import android.webkit.WebView

class MainActivity : Activity() {

    private var webView: WebView? = null
    private val mainResult: ProbeResult = ProbeResult.probe()
    private val capMain: String = CapabilityReport.scan()

    private val connection: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            Log.i(TAG, "onServiceConnected: $binder")
            val server = IZygoteNextProbeService.Stub.asInterface(binder)
            try {
                val raw = server.getResult()
                Log.i(TAG, "getResult raw=[$raw]")
                val parsed = ProbeResult.parse(raw)
                Log.i(TAG, "parsed=$parsed")
                val caps = safeCaps(server)
                Log.i(TAG, "caps head=" + (caps?.take(80) ?: "null"))
                val report = buildReport(parsed, caps)
                Log.i(TAG, "report:\n$report")
                setText(report)
            } catch (e: Exception) {
                Log.e(TAG, "report generation failed", e)
                setText("ERROR: " + Log.getStackTraceString(e))
            }
            unbindService(connection)
        }

        private fun safeCaps(server: IZygoteNextProbeService): String? = try {
            server.getCapabilities()
        } catch (e: RemoteException) {
            "(capabilities unavailable: ${e.message})"
        }

        override fun onServiceDisconnected(name: ComponentName) {
        }

        override fun onNullBinding(name: ComponentName) {
            setText(
                "INFO: service did not bind (native zygote path).\n\n" +
                    "This device routes android:nativeService isolated processes to zygote_next " +
                    "(ppid of the service process == zygote_next).\n\n" +
                    "Probe report is printed to logcat under tag $TAG:\n" +
                    "  adb logcat -s $TAG\n\n" +
                    "Key signals: mnt ns inode (expect 4026531841 == init's global ns) and root " +
                    "mount propagation (expect shared:N instead of classic master:N)."
            )
            unbindService(connection)
        }
    }

    private fun fmtNs(inode: Long): String =
        if (inode == 0L) "unreadable" else "mnt:[$inode]"

    private fun buildReport(isolated: ProbeResult, capIsolated: String?): String {
        val sb = StringBuilder()

        sb.append("== PROCESSES ==\n")
        sb.append("main process      pid=").append(mainResult.pid)
            .append(" isolated=").append(mainResult.isolated).append('\n')
        sb.append("isolated process  pid=").append(isolated.pid)
            .append(" isolated=").append(isolated.isolated).append('\n')
        sb.append('\n')

        sb.append("== PROC CAPABILITY (AID_READPROC / hidepid) ==\n")
        sb.append(capMain).append('\n')
        sb.append("--- isolated process ---\n")
        sb.append(capIsolated ?: "(unavailable)").append('\n')
        sb.append("--- analysis ---\n").append(capAnalysis(capMain, capIsolated)).append('\n')

        sb.append("== MOUNT NAMESPACE (mnt ns inode, best effort) ==\n")
        sb.append("self      ").append(fmtNs(mainResult.mntNsSelf)).append('\n')
        sb.append("isolated  ").append(fmtNs(isolated.mntNsSelf)).append('\n')
        sb.append("init(pid 1) ").append(fmtNs(mainResult.mntNsInit))
        if (!mainResult.proc1Readable) {
            sb.append("  [untrusted_app cannot read /proc/1: kernel DAC ptrace_may_access blocks it]")
        }
        sb.append('\n')
        sb.append('\n')

        sb.append("== ZYGOTE_NEXT ==\n")
        when {
            mainResult.zygoteNext -> sb.append("running: YES\n")
            !mainResult.proc1Readable ->
                sb.append("running: UNKNOWN (comm scan blocked: root processes are DAC-unreadable)\n")
            else -> sb.append("running: not found\n")
        }
        sb.append("properties: ").append(
            if (mainResult.zygoteNextProps.isEmpty()) "(none readable)" else mainResult.zygoteNextProps
        ).append('\n')
        sb.append('\n')

        sb.append("== ROOT MOUNT PROPAGATION (core signal) ==\n")
        sb.append("self      ").append(describePropagation(mainResult.selfPropagation)).append('\n')
        sb.append("isolated  ").append(describePropagation(isolated.selfPropagation)).append('\n')
        sb.append('\n')

        sb.append("== MOUNTINFO (md5 of own /proc/self/mountinfo) ==\n")
        sb.append("self      ").append(mainResult.selfFingerprint ?: "(unreadable)").append('\n')
        sb.append("isolated  ").append(isolated.selfFingerprint ?: "(unreadable)").append('\n')
        sb.append('\n')

        sb.append("== ROOT MARKERS IN OWN MOUNTINFO ==\n")
        sb.append(if (mainResult.rootMarkers.isEmpty()) "(none found)" else mainResult.rootMarkers)
            .append('\n')
        sb.append('\n')

        sb.append("== VERDICT ==\n").append(verdict(isolated))

        return sb.toString()
    }

    private fun describePropagation(propagation: String): String = when {
        propagation.isEmpty() -> "(no propagation info)"
        propagation.startsWith("master:") ->
            "$propagation (slave view: private mount namespace, classic zygote64)"
        propagation.startsWith("shared:") ->
            "$propagation (shared view: global/init mount namespace, zygote_next)"
        else -> propagation
    }

    private fun verdict(isolated: ProbeResult): String {
        val mainProp = mainResult.selfPropagation
        val isoProp = isolated.selfPropagation
        val mainShared = mainProp.startsWith("shared:")
        val isoShared = isoProp.startsWith("shared:")

        val sb = StringBuilder()
        if (mainShared) {
            sb.append(
                "DETECTED: app runs in the GLOBAL mount namespace (zygote_next signature). " +
                    "Root mount propagation is $mainProp (shared, same view as init/pid 1). " +
                    "zygote_next forks with a plain fork() and never unshares CLONE_NEWNS, so every " +
                    "app inherits init's global mount namespace. Per-app mount isolation is gone " +
                    "and mount hiding is ineffective.\n"
            )
        } else if (mainProp.startsWith("master:")) {
            sb.append(
                "NOT zygote_next: app runs in a private (slave) mount namespace " +
                    "(classic zygote64 forked this process). This probe targets zygote_next only.\n"
            )
        } else {
            sb.append(
                "INFO: no propagation info on root mount; cannot classify (device/vendor variant).\n"
            )
        }

        if (mainShared && isoShared) {
            sb.append("Isolated process agrees: also in the shared global view.\n")
        } else if (isoShared && !mainShared) {
            sb.append(
                "CONTRAST: the native isolated service (android:nativeService path, forked by " +
                    "zygote_next) runs in the GLOBAL mount namespace ($isoProp, shared view, " +
                    "mnt ns 4026531841 == init), while the classic zygote64-forked main process " +
                    "keeps a private (master) namespace. zygote_next forks with plain fork() and " +
                    "never unshares CLONE_NEWNS, so its children inherit init's global mount " +
                    "view - per-app mount isolation and mount hiding are ineffective there.\n"
            )
        } else if (mainShared && !isoShared) {
            sb.append("Isolated process differs: ${isoProp.ifEmpty { "(unreadable)" }} (unexpected)\n")
        }

        if (mainResult.mntNsInit != 0L) {
            sb.append("Cross-check (privileged view): init ns inode=").append(mainResult.mntNsInit)
                .append(" vs self=").append(mainResult.mntNsSelf).append('\n')
        }
        if (mainResult.rootMarkers.isNotEmpty()) {
            sb.append("Root-hiding mounts are visible in this process's mount view: ")
                .append(mainResult.rootMarkers).append('\n')
        }
        return sb.toString()
    }

    private fun capAnalysis(capMain: String, capIsolated: String?): String {
        val mainGroups = extractField(capMain, "groups")
        val isoGroups = capIsolated?.let { extractField(it, "groups") }
        val mainTotal = extractField(capMain, "pids total")
        val isoTotal = capIsolated?.let { extractField(it, "pids total") }
        val isoUnreadable = capIsolated?.let { extractField(it, "pids unreadable") }
        val procMount = extractField(capMain, "proc mount")

        val sb = StringBuilder()
        if (isoGroups != null && isoGroups.contains("3009")) {
            sb.append(
                "CONFIRMED: isolated process inherited AID_READPROC (group 3009) from zygote. " +
                    "Children keep zygote's supplementary groups (groups=$mainGroups). " +
                    "On zygote_next devices this group is not expected - zygote_next's .rc stanza " +
                    "only grants 'group root' and its spawn path skips setgroups when the gids " +
                    "list is empty (child_process.rs:93).\n"
            )
        } else {
            sb.append("no AID_READPROC (3009) in isolated groups (groups=$isoGroups)\n")
        }
        if (procMount != null && procMount.contains("hidepid")) {
            sb.append(
                "This device's /proc uses $procMount; the inherited group " +
                    "3009 bypasses the hidepid filter, so the process can enumerate and read " +
                    "the whole isolated_app class (all WebView renderers + self).\n"
            )
        }
        val mainPids = parseInt(extractFirstToken(mainTotal))
        val isoPids = parseInt(extractFirstToken(isoTotal))
        if (isoPids > mainPids && mainPids > 0) {
            sb.append("PID visibility: main untrusted_app sees $mainPids")
            sb.append(", isolated sees $isoPids")
            sb.append(" — hidepid=invisible is bypassed by the inherited group.\n")
        }
        val isoUn = extractFirstToken(isoUnreadable)
        if (isoUn != null && parseInt(isoUn) == 0) {
            sb.append("Isolated process reads EVERY visible /proc/<pid> entry (unreadable=0), ")
            sb.append("including OTHER apps' isolated processes (WebView renderers).\n")
        }
        return sb.toString()
    }

    private fun setText(text: String) {
        val html = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {
                        margin: 0;
                        padding: 16px;
                        padding-top: env(safe-area-inset-top);
                        box-sizing: border-box;
                        font-family: monospace;
                        font-size: 14px;
                        line-height: 1.5;
                        word-break: break-all;
                        overflow-wrap: break-word;
                    }
                    pre {
                        margin: 0;
                        white-space: pre-wrap;
                    }
                </style>
            </head>
            <body>
                <pre>$text</pre>
            </body>
            </html>
        """.trimIndent()
        webView?.loadDataWithBaseURL(null, html, "text/html", "utf-8", null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.subtitle = BuildConfig.VERSION_NAME

        webView = WebView(this)
        setText("INFO: Waiting for isolated service...")
        setContentView(webView)
        try {
            val bound = bindIsolatedService(
                Intent(this, ZygoteNextProbeService::class.java),
                Context.BIND_AUTO_CREATE,
                "zygote_next_probe",
                mainExecutor,
                connection
            )
            if (!bound) {
                setText("ERROR: Failed to bind service, service disabled?")
                unbindService(connection)
            }
        } catch (e: SecurityException) {
            setText(Log.getStackTraceString(e))
            unbindService(connection)
        }
    }

    companion object {
        private const val TAG = "ZygoteNextProbe"

        private fun extractField(report: String, key: String): String? {
            val prefix = "$key: "
            for (line in report.split("\n")) {
                if (line.startsWith(prefix)) {
                    return line.substring(prefix.length).trim()
                }
            }
            return null
        }

        private fun extractFirstToken(s: String?): String? = s?.split(" ")?.first()

        private fun parseInt(s: String?): Int = try {
            s!!.toInt()
        } catch (e: Exception) {
            -1
        }
    }
}
