package io.github.xiaotong6666.zygotenextprobe

import android.os.Process
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.HexFormat

data class ProbeResult(
    val pid: Int,
    val isolated: Boolean,
    val mntNsSelf: Long,
    val mntNsInit: Long,
    val proc1Readable: Boolean,
    val mntNsZygoteNext: Long,
    val zygoteNext: Boolean,
    val selfFingerprint: String?,
    val selfPropagation: String,
    val zygoteNextProps: String,
    val rootMarkers: String,
) {

    fun toLine(): String = listOf(
        pid, isolated, mntNsSelf, mntNsInit, proc1Readable, mntNsZygoteNext, zygoteNext,
        selfFingerprint.orEmpty(), selfPropagation, zygoteNextProps, rootMarkers
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
                selfFingerprint = fingerprint("/proc/self/mountinfo"),
                selfPropagation = propagationOf("/proc/self/mountinfo"),
                zygoteNextProps = readZygoteNextProps(),
                rootMarkers = scanRootMarkers(),
            )
        }

        fun parse(line: String): ProbeResult {
            val p = line.split("|", limit = 12)
            return ProbeResult(
                pid = p[0].toInt(),
                isolated = p[1].toBoolean(),
                mntNsSelf = p[2].toLong(),
                mntNsInit = p[3].toLong(),
                proc1Readable = p[4].toBoolean(),
                mntNsZygoteNext = p[5].toLong(),
                zygoteNext = p[6].toBoolean(),
                selfFingerprint = p[7].ifEmpty { null },
                selfPropagation = p[8],
                zygoteNextProps = p[9],
                rootMarkers = p[10],
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

        private fun fingerprint(path: String): String? = try {
            Files.newInputStream(Path.of(path)).use { input ->
                val md = MessageDigest.getInstance("MD5")
                val buf = ByteArray(8192)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                }
                HexFormat.of().formatHex(md.digest())
            }
        } catch (e: IOException) {
            null
        } catch (e: NoSuchAlgorithmException) {
            null
        }

        /**
         * Core signal: mount propagation of the root mount as seen by this process.
         * Classic zygote unshares CLONE_NEWNS and remounts / with MS_SLAVE|MS_REC,
         * so app processes see "master:N" (slave of the parent's master group).
         * zygote_next forks without any unshare, so apps keep init's global view,
         * where the root mount carries "shared:N". The app can read its own
         * /proc/self/mountinfo without any cross-process permission.
         */
        private fun propagationOf(path: String): String = try {
            Files.newBufferedReader(Path.of(path)).use { reader ->
                val line = reader.readLine() ?: return ""
                val pre = line.substringBefore(" - ")
                pre.split(" ")
                    .filter { it.startsWith("shared:") || it.startsWith("master:") }
                    .joinToString(" ")
            }
        } catch (e: IOException) {
            ""
        }

        private fun scanRootMarkers(): String = try {
            Files.newBufferedReader(Path.of("/proc/self/mountinfo")).use { reader ->
                buildList {
                    for (line in reader.lineSequence()) {
                        if (line.contains("magisk") || line.contains("ksu") || line.contains("KSU")
                            || line.contains("/adb/") || line.contains("/debug_ramdisk")
                        ) {
                            try {
                                val info = MountInfo.parseLine(line)
                                add("${info.point} [${info.type}]")
                            } catch (ignored: RuntimeException) {
                            }
                        }
                    }
                }.joinToString(", ")
            }
        } catch (e: IOException) {
            ""
        }
    }
}
