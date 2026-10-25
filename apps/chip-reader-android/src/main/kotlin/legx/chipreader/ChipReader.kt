package legx.chipreader

import android.nfc.Tag
import android.nfc.tech.IsoDep
import net.sf.scuba.smartcards.CardService
import org.jmrtd.BACKey
import org.jmrtd.PassportService
import org.jmrtd.lds.icao.DG15File
import java.security.MessageDigest

/**
 * Reads the chip and answers Active Authentication with the console's own 8-byte challenge.
 * UNBUILT AND UNTESTED: names follow the JMRTD Javadoc and may differ in your version.
 * Sources: https://www.javadoc.io/static/org.jmrtd/jmrtd/0.7.35/org/jmrtd/PassportService.html
 *          https://developer.android.com/reference/android/nfc/tech/IsoDep
 */
fun readChip(tag: Tag, mrzKey: BACKey, challenge: ByteArray): ChipData {
    require(challenge.size == 8) { "RND.IFD is 8 bytes (ICAO 9303 Part 11, 6.1.2.1)" }
    val isoDep = IsoDep.get(tag)
    isoDep.timeout = 10_000 // reads of DG15 and EF.SOD are slow
    val service = PassportService(
        CardService.getInstance(isoDep),
        PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false,
        false,
    )
    service.open()
    service.sendSelectApplet(false)
    // TODO(JMRTD): try PACE first (CardAccess), fall back to BAC; both need the MRZ-derived key.
    service.doBAC(mrzKey)

    fun file(fid: Short): ByteArray? = try {
        service.getInputStream(fid).readBytes()
    } catch (e: Exception) {
        null // the file is absent on this chip
    }

    val dg1 = file(PassportService.EF_DG1) ?: error("no DG1")
    val sod = file(PassportService.EF_SOD) ?: error("no EF.SOD")
    val dg14 = file(PassportService.EF_DG14)
    val dg15 = file(PassportService.EF_DG15)

    // Active Authentication with OUR challenge, not a random one: this binds the chip's answer to presenceMsg.
    val aaSignature = dg15?.let {
        val pub = DG15File(it.inputStream()).publicKey
        service.doAA(pub, null, null, challenge).response
    }
    return ChipData(dg1, sod, dg14, dg15, aaSignature)
}
