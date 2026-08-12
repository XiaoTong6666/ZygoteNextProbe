package io.github.xiaotong6666.zygotenextprobe

import android.os.Process
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.TreeMap

object CapabilityReport {

    fun scan(): String {
        val sb = StringBuilder()
        val status = read("/proc/self/status")
        sb.append("groups: ").append(extract(status, "Groups")).append('\n')
        sb.append("uid: ").append(extract(status, "Uid")).append('\n')
        sb.append("context: ").append(read("/proc/self/attr/current")).append('\n')
        sb.append("proc mount: ").append(procMountOptions()).append('\n')

        val myUid = Process.myUid()
        val classes = TreeMap<String, Int>()
        val targets = mutableListOf<String>()
        var total = 0
        var unreadable = 0
        try {
            Files.newDirectoryStream(Path.of("/proc")) { Files.isDirectory(it) }.use { dir ->
                for (path in dir) {
                    val name = path.fileName.toString()
                    if (!name.all(Char::isDigit)) continue
                    total++
                    val s = read("/proc/$name/status")
                    val ctx = read("/proc/$name/attr/current")
                    if (s != null) {
                        val cls = classify(name, s, ctx, myUid)
                        classes.merge(cls, 1) { a, b -> a + b }
                        if (isInteresting(cls)) {
                            targets.add("$name=$cls[${shortCtx(ctx)}]")
                        }
                    } else {
                        unreadable++
                    }
                }
            }
        } catch (ignored: IOException) {
        }
        sb.append("pids total: ").append(total).append('\n')
        sb.append("pids unreadable: ").append(unreadable)
            .append(" (").append(if (total == 0) 0 else unreadable * 100 / total).append("%)\n")
        sb.append("readable by class: ").append(classes).append('\n')
        if (targets.isNotEmpty()) {
            val limit = minOf(12, targets.size)
            sb.append("targets: ").append(targets.subList(0, limit).joinToString(", "))
            if (targets.size > limit) {
                sb.append(", ...(").append(targets.size - limit).append(" more)")
            }
            sb.append('\n')
            sb.append("target mounts: ").append(detailTargets(targets, limit)).append('\n')
        } else {
            sb.append("targets: (none readable)\n")
        }
        return sb.toString()
    }

    private fun detailTargets(targets: List<String>, limit: Int): String {
        val details = mutableListOf<String>()
        for (t in targets.subList(0, minOf(3, limit))) {
            val pid = t.substringBefore('=')
            val ns = readNs("/proc/$pid/ns/mnt")
            val firstMount = firstMountInfoLine("/proc/$pid/mountinfo")
            details.add("$pid mntns=$ns mountinfo1=$firstMount")
        }
        return details.joinToString(" | ")
    }

    private fun firstMountInfoLine(path: String): String = try {
        val line = Files.readAllLines(Path.of(path))[0]
        if (line.length > 100) line.substring(0, 100) + "..." else line
    } catch (e: IOException) {
        "(unreadable)"
    }

    private fun readNs(path: String): Long = try {
        val target = Files.readSymbolicLink(Path.of(path)).toString()
        target.substring(target.indexOf('[') + 1, target.indexOf(']')).toLong()
    } catch (e: IOException) {
        0
    } catch (e: RuntimeException) {
        0
    }

    private fun extract(status: String?, key: String): String {
        if (status == null) return "(unreadable)"
        val prefix = "$key:"
        for (line in status.split("\n")) {
            if (line.startsWith(prefix)) {
                return line.substring(prefix.length).trim()
            }
        }
        return "(missing)"
    }

    private fun classify(pid: String, status: String, ctx: String?, myUid: Int): String {
        val uidLine = extract(status, "Uid")
        if (!uidLine.startsWith("(")) {
            try {
                if (uidLine.trim().split(Regex("\\s+"))[0].toInt() == myUid) return "same-uid"
            } catch (ignored: NumberFormatException) {
            }
        }
        if (ctx == null) return "noctx"
        return when {
            ctx.contains("isolated_app") -> "isolated_app"
            ctx.contains("webview_zygote") -> "webview_zygote"
            ctx.contains(":zygote") -> "zygote"
            ctx.contains("system_server") -> "system_server"
            ctx.contains(":init") -> "init"
            ctx.contains("untrusted_app") -> "untrusted_app"
            ctx.contains("shell") -> "shell"
            ctx.contains(":ksu") -> "ksu"
            else -> "other:${shortCtx(ctx)}"
        }
    }

    private fun isInteresting(cls: String): Boolean =
        cls == "isolated_app" || cls == "webview_zygote" || cls == "zygote"
            || cls == "system_server" || cls == "init" || cls == "ksu" || cls == "untrusted_app"

    private fun shortCtx(ctx: String?): String {
        if (ctx == null) return "?"
        val end = ctx.indexOf(":s0")
        return if (end > 0) ctx.substring(0, end) else ctx
    }

    private fun procMountOptions(): String = try {
        Files.newBufferedReader(Path.of("/proc/self/mountinfo")).use { reader ->
            for (line in reader.lineSequence()) {
                val sep = line.indexOf(" - ")
                if (sep < 0) continue
                val after = line.substring(sep + 3).split(" ")
                if (after.size < 3 || after[0] != "proc") continue
                val pre = line.substring(0, sep).split(" ")
                return "${pre[4]} opts=${pre[5]} super=${after[2]}"
            }
            "(not found)"
        }
    } catch (e: IOException) {
        "(unreadable)"
    }

    private fun read(path: String): String? = try {
        Files.readString(Path.of(path)).trim()
    } catch (e: IOException) {
        null
    }
}
