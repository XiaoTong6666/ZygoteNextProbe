package io.github.xiaotong6666.zygotenextprobe

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths

data class MountInfo(
    val id: Int,
    val parent: Int,
    val device: Long,
    val root: String,
    val point: String,
    val options: String,
    val optional: String,
    val type: String,
    val source: String,
    val superOptions: String,
) : Comparable<MountInfo> {

    override fun compareTo(other: MountInfo): Int {
        val cmp = Integer.compareUnsigned(peerGroup, other.peerGroup)
        if (cmp != 0) return cmp
        val pointCmp = point.compareTo(other.point)
        if (pointCmp != 0) return pointCmp
        return Integer.compareUnsigned(id, other.id)
    }

    val peerGroup: Int
        get() {
            val colonPos = optional.indexOf(':')
            if (colonPos == -1) return 0
            var spacePos = optional.indexOf(' ', colonPos)
            if (spacePos == -1) spacePos = optional.length
            return Integer.parseUnsignedInt(optional.substring(colonPos + 1, spacePos))
        }

    companion object {

        fun scan(pid: String): List<MountInfo> = try {
            Files.newBufferedReader(Paths.get("/proc", pid, "mountinfo")).use { reader ->
                reader.lineSequence().map { parseLine(it) }.toList()
            }
        } catch (e: IOException) {
            emptyList()
        }

        fun parseLine(line: String): MountInfo {
            var cursor = 0

            var nextSpace = line.indexOf(' ', cursor)
            val id = Integer.parseUnsignedInt(line, cursor, nextSpace, 10)
            cursor = nextSpace + 1

            nextSpace = line.indexOf(' ', cursor)
            val parent = Integer.parseUnsignedInt(line, cursor, nextSpace, 10)
            cursor = nextSpace + 1

            nextSpace = line.indexOf(' ', cursor)
            val colonPos = line.indexOf(':', cursor)
            val major = Integer.parseUnsignedInt(line, cursor, colonPos, 10)
            val minor = Integer.parseUnsignedInt(line, colonPos + 1, nextSpace, 10)
            val device = makeDev(major, minor)
            cursor = nextSpace + 1

            nextSpace = line.indexOf(' ', cursor)
            val root = line.substring(cursor, nextSpace)
            cursor = nextSpace + 1

            nextSpace = line.indexOf(' ', cursor)
            val point = line.substring(cursor, nextSpace)
            cursor = nextSpace + 1

            nextSpace = line.indexOf(' ', cursor)
            val options = line.substring(cursor, nextSpace)
            cursor = nextSpace

            val separatorPos = line.indexOf(" - ", cursor)
            val optional = line.substring(cursor, separatorPos).trim()
            cursor = separatorPos + 3

            nextSpace = line.indexOf(' ', cursor)
            val type = line.substring(cursor, nextSpace)
            cursor = nextSpace + 1

            nextSpace = line.indexOf(' ', cursor)
            val source = line.substring(cursor, nextSpace)
            cursor = nextSpace + 1

            val superOptions = line.substring(cursor)

            return MountInfo(id, parent, device, root, point, options, optional, type, source, superOptions)
        }

        private fun makeDev(major: Int, minor: Int): Long =
            (major.toLong() shl 32) or ((major and 0xfff).toLong() shl 8) or
                (minor.toLong() shl 12) or (minor and 0xff).toLong()
    }
}
