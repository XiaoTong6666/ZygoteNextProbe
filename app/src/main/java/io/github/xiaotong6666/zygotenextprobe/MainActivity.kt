package io.github.xiaotong6666.zygotenextprobe

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Typeface
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.view.ViewGroup
import android.view.WindowInsets
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {

    private lateinit var reportView: TextView
    private val mainResult: ProbeResult = ProbeResult.probe()

    private val connection: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            Log.i(TAG, "onServiceConnected: $binder")
            val server = IZygoteNextProbeService.Stub.asInterface(binder)
            try {
                val raw = server.getResult()
                Log.i(TAG, "getResult raw=[$raw]")
                val parsed = ProbeResult.parse(raw)
                Log.i(TAG, "parsed=$parsed")
                val report = buildReport(parsed)
                Log.i(TAG, "report:\n$report")
                setText(report)
            } catch (e: Exception) {
                Log.e(TAG, "report generation failed", e)
                setText("ERROR: " + Log.getStackTraceString(e))
            }
            unbindService(connection)
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
                    "Key signal: root mount propagation (expect shared:N instead of classic " +
                    "master:N)."
            )
            unbindService(connection)
        }
    }

    private fun fmtNs(inode: Long): String =
        if (inode == 0L) "unreadable" else "mnt:[$inode]"

    private fun buildReport(isolated: ProbeResult): String {
        val sb = StringBuilder()

        sb.append("== PROCESSES ==\n")
        sb.append("main process      pid=").append(mainResult.pid)
            .append(" isolated=").append(mainResult.isolated).append('\n')
        sb.append("isolated process  pid=").append(isolated.pid)
            .append(" isolated=").append(isolated.isolated).append('\n')
        sb.append('\n')

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

        sb.append("== ROOT MARKERS IN OWN MOUNTINFO ==\n")
        sb.append("main process view (untrusted_app, private slave ns):\n  ")
            .append(if (mainResult.rootMarkers.isEmpty()) "(none found)" else mainResult.rootMarkers)
            .append('\n')
        sb.append("isolated process view (zygote_next shared view):\n  ")
            .append(if (isolated.rootMarkers.isEmpty()) "(none found)" else isolated.rootMarkers)
            .append('\n')
        if (isolated.rootMarkers.isNotEmpty() && mainResult.rootMarkers.isEmpty()) {
            sb.append("NOTE: root mounts are visible ONLY in the zygote_next shared view. The " +
                "classic main-process view does not contain them, so mount hiding did not cover " +
                "the zygote_next-spawned process.\n")
        } else if (isolated.rootMarkers.isNotEmpty()
            && isolated.rootMarkers != mainResult.rootMarkers
        ) {
            sb.append("NOTE: mount views differ between the two namespaces - compare the two " +
                "lists above.\n")
        }
        sb.append("Scope: markers come from /proc/self/mountinfo only. A missing Sui, KernelSU, " +
            "ZN, or Zygisk label does not mean the corresponding process or software is absent.\n")
        sb.append('\n')

        sb.append("== VERDICT ==\n").append(verdict(isolated))

        return sb.toString()
    }

    private fun describePropagation(propagation: String): String = when {
        propagation.isEmpty() -> "(no propagation info)"
        propagation.startsWith("master:") ->
            "$propagation (slave view: private mount namespace, classic zygote64)"
        propagation.startsWith("shared:") ->
            "$propagation (shared propagation: zygote_next global-view signature)"
        else -> propagation
    }

    private fun verdict(isolated: ProbeResult): String {
        val mainProp = mainResult.selfPropagation
        val isoProp = isolated.selfPropagation
        val mainShared = mainProp.startsWith("shared:")
        val isoShared = isoProp.startsWith("shared:")

        val sb = StringBuilder()
        if (isoShared && !mainShared) {
            sb.append(
                "DETECTED / CONTRAST: the native isolated service runs with $isoProp and mount " +
                    "namespace ${fmtNs(isolated.mntNsSelf)}, while the classic zygote64 main " +
                    "process keeps $mainProp and ${fmtNs(mainResult.mntNsSelf)}. AOSP zygote_next " +
                    "uses plain fork() without CLONE_NEWNS, so this shared view is inherited from " +
                    "the zygote_next parent; per-app mount hiding did not cover this path.\n"
            )
        } else if (mainShared) {
            sb.append(
                "DETECTED: the main process has shared root propagation $mainProp, a global-view " +
                    "signature. Its mount namespace is ${fmtNs(mainResult.mntNsSelf)}.\n"
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
        } else if (mainShared && !isoShared) {
            sb.append("Isolated process differs: ${isoProp.ifEmpty { "(unreadable)" }} (unexpected)\n")
        }

        if (mainResult.mntNsInit != 0L) {
            sb.append("Cross-check (privileged view): init ns inode=").append(mainResult.mntNsInit)
                .append(" vs self=").append(mainResult.mntNsSelf).append('\n')
        }
        if (isolated.rootMarkers.isNotEmpty()) {
            sb.append("ROOT LEAK: root mounts visible from the zygote_next-spawned process " +
                "(isolated, scanned via /proc/self/mountinfo): ")
                .append(isolated.rootMarkers).append('\n')
        }
        return sb.toString()
    }

    private fun setText(text: String) {
        reportView.text = text
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.subtitle = BuildConfig.VERSION_NAME

        val padding = (16 * resources.displayMetrics.density).toInt()
        reportView = TextView(this).apply {
            setPadding(padding, padding, padding, padding)
            typeface = Typeface.MONOSPACE
            textSize = 14f
            setTextIsSelectable(true)
        }
        val reportScroller = ScrollView(this).apply {
            isFillViewport = true
            setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.getInsets(
                    WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout(),
                )
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                insets
            }
            addView(
                reportView,
                ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
        setText("INFO: Waiting for isolated service...")
        setContentView(reportScroller)
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
    }
}
