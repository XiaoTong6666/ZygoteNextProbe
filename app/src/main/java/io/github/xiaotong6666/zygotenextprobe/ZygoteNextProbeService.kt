package io.github.xiaotong6666.zygotenextprobe

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process

class ZygoteNextProbeService : Service() {

    private val binder = object : IZygoteNextProbeService.Stub() {
        override fun getResult(): String = ProbeResult.probe().toLine()

        override fun getCapabilities(): String = CapabilityReport.scan()
    }

    override fun onBind(intent: Intent): IBinder? =
        if (Process.isIsolated()) binder else null
}
