package io.github.xiaotong6666.zygotenextprobe

import android.os.Process
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

data class ProbeResult(
    val pid: Int,
    val isolated: Boolean,
    val mntNsSelf: Long,
    val mntNsInit: Long,
    val proc1Readable: Boolean,
    val mntNsZygoteNext: Long,
    val zygoteNext: Boolean,
    val selfPropagation: String,
    val zygoteNextProps: String,
    val rootMarkers: String,
) {

    fun toLine(): String = listOf(
        pid, isolated, mntNsSelf, mntNsInit, proc1Readable, mntNsZygoteNext, zygoteNext,
        selfPropagation, zygoteNextProps, rootMarkers
    ).joinToString("|")

    companion object {

        fun probe(): ProbeResult {
            val zygoteNextPid = findZygoteNext()
            return ProbeResult(
                pid = Process.myPid(),
                isolated = Process.isIsolated(),
                mntNsSelf = readNs("/proc/self/ns/mnt"),
                mntNsInit = readNs("/proc/1/ns/mnt"),
                proc1Readable = isReadable("/proc/1/comm"),
                mntNsZygoteNext = if (zygoteNextPid > 0) readNs("/proc/$zygoteNextPid/ns/mnt") else 0,
                zygoteNext = zygoteNextPid > 0,
                selfPropagation = propagationOf("/proc/self/mountinfo"),
                zygoteNextProps = readZygoteNextProps(),
                rootMarkers = scanRootMarkers(),
            )
        }

        fun parse(line: String): ProbeResult {
            val p = line.split("|", limit = 11)
            return ProbeResult(
                pid = p[0].toInt(),
                isolated = p[1].toBoolean(),
                mntNsSelf = p[2].toLong(),
                mntNsInit = p[3].toLong(),
                proc1Readable = p[4].toBoolean(),
                mntNsZygoteNext = p[5].toLong(),
                zygoteNext = p[6].toBoolean(),
                selfPropagation = p[7],
                zygoteNextProps = p[8],
                rootMarkers = p[9],
            )
        }

        private fun readNs(path: String): Long = try {
            val target = Files.readSymbolicLink(Path.of(path)).toString()
            target.substring(target.indexOf('[') + 1, target.indexOf(']')).toLong()
        } catch (e: IOException) {
            0
        } catch (e: RuntimeException) {
            0
        }

        private fun isReadable(path: String): Boolean = try {
            Files.readString(Path.of(path))
            true
        } catch (e: IOException) {
            false
        }

        private fun findZygoteNext(): Int = try {
            Files.newDirectoryStream(Path.of("/proc")) { Files.isDirectory(it) }.use { stream ->
                for (path in stream) {
                    val name = path.fileName.toString()
                    if (!name.all(Char::isDigit)) continue
                    try {
                        if (Files.readString(Path.of("/proc", name, "comm")).trim().contains("zygote_next")) {
                            return name.toInt()
                        }
                    } catch (ignored: IOException) {
                    }
                }
                0
            }
        } catch (e: IOException) {
            0
        }

        private fun readZygoteNextProps(): String {
            val ready = getProp("zygote.zygote_next.server_ready")
            val start = getProp("persist.zygote.zygote_next.start_on_boot")
            return buildList {
                if (ready.isNotEmpty()) add("server_ready=$ready")
                if (start.isNotEmpty()) add("start_on_boot=$start")
            }.joinToString(", ")
        }

        private fun getProp(name: String): String = try {
            val clazz = Class.forName("android.os.SystemProperties")
            clazz.getMethod("get", String::class.java).invoke(null, name) as String
        } catch (e: Exception) {
            ""
        }

        /**
         * Core signal: mount propagation of the root mount as seen by this process.
         * Classic zygote unshares CLONE_NEWNS and remounts / with MS_SLAVE|MS_REC,
         * so app processes see "master:N" (slave of the parent's master group).
         * zygote_next forks without any unshare, producing the "shared:N"
         * global-view signature. The app can read its own /proc/self/mountinfo
         * without any cross-process permission.
         */
        private fun propagationOf(path: String): String = try {
            Files.newBufferedReader(Path.of(path)).use { reader ->
                val rootMount = reader.lineSequence().mapNotNull { line ->
                    try {
                        MountInfo.parseLine(line)
                    } catch (ignored: RuntimeException) {
                        null
                    }
                }.firstOrNull { it.point == "/" } ?: return ""
                rootMount.optional.split(" ")
                    .filter { it.startsWith("shared:") || it.startsWith("master:") }
                    .joinToString(" ")
            }
        } catch (e: IOException) {
            ""
        }

        /**
         * Scan this process's mount view for known root and injection markers.
         * Matching is case-insensitive and the result reports actual mountpoints.
         */
        private fun scanRootMarkers(): String = try {
            Files.newBufferedReader(Path.of("/proc/self/mountinfo")).use { reader ->
                buildList {
                    for (line in reader.lineSequence()) {
                        val labels = markerLabels(line)
                        if (labels.isNotEmpty()) {
                            try {
                                val info = MountInfo.parseLine(line)
                                add(
                                    "${labels.joinToString("+")}: ${info.point} " +
                                        "[${info.type}; root=${info.root}; source=${info.source}]",
                                )
                            } catch (ignored: RuntimeException) {
                            }
                        }
                    }
                }.joinToString(", ")
            }
        } catch (e: IOException) {
            ""
        }

        private fun markerLabels(line: String): List<String> {
            val normalized = line.lowercase()
            return buildList {
                if (containsNamedMarker(normalized, "zn", true)) add("ZN")
                if (normalized.contains("zygisk")) add("Zygisk")
                if (containsNamedMarker(normalized, "sui", true)) add("Sui")
                if (normalized.contains("kernelsu") ||
                    containsNamedMarker(normalized, "ksu", true)
                ) {
                    add("KernelSU")
                }
                if (containsNamedMarker(normalized, "lsp", false)) add("LSP")
                if (normalized.contains("magisk")) add("Magisk")
                if (normalized.contains("/adb/")) add("ADB")
                if (normalized.contains("/debug_ramdisk")) add("debug_ramdisk")
            }
        }

        private fun containsNamedMarker(
            text: String,
            marker: String,
            requireEnd: Boolean,
        ): Boolean {
            var start = text.indexOf(marker)
            while (start >= 0) {
                val end = start + marker.length
                val startBoundary = start == 0 || !text[start - 1].isLetterOrDigit()
                val endBoundary = !requireEnd || end == text.length || !text[end].isLetterOrDigit()
                if (startBoundary && endBoundary) return true
                start = text.indexOf(marker, start + 1)
            }
            return false
        }
    }
}
