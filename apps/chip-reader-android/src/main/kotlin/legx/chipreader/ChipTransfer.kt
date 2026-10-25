package legx.chipreader

import java.io.ByteArrayOutputStream

/**
 * The chip-link transfer format; mirrors packages/chip-link/src/wire.ts.
 * "LGXC" || version(1) || fields of tag(1) || length(4, big endian) || value, tags ascending.
 * UNBUILT AND UNTESTED.
 */
class ChipData(
    val dg1: ByteArray,
    val sod: ByteArray,
    val dg14: ByteArray?,
    val dg15: ByteArray?,
    val aaSignature: ByteArray?,
)

fun encode(d: ChipData): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(byteArrayOf(0x4c, 0x47, 0x58, 0x43, 1))
    listOf(1 to d.dg1, 2 to d.sod, 3 to d.dg14, 4 to d.dg15, 5 to d.aaSignature).forEach { (tag, v) ->
        if (v == null) return@forEach
        out.write(tag)
        out.write(byteArrayOf((v.size ushr 24).toByte(), (v.size ushr 16).toByte(), (v.size ushr 8).toByte(), v.size.toByte()))
        out.write(v)
    }
    return out.toByteArray()
}
