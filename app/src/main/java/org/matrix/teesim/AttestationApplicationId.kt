package org.matrix.teesim

import android.content.pm.PackageInfo
import android.os.Build
import android.os.Process
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet

/**
 * DER `AttestationApplicationId` as AOSP Keystore1 builds it:
 * `system/security/keystore/keystore_attestation_id.cpp` (`android11-release`) plus
 * `KeyAttestationApplicationIdProviderService` (`GET_SIGNATURES`).
 *
 * `gather_attestation_application_id` uses a fixed `AndroidSystem` record for
 * `AID_SYSTEM`. Other uids take `getPackagesForUid` order, each package's name
 * and version, and SHA-256 of `PackageInfo.signatures` of the first package.
 * Encoding stops before the DER would exceed 1024 bytes.
 */
object AttestationApplicationId {

    private const val MAX_ENCODED = 1024
    private const val GENERAL_OVERHEAD = 16
    private const val PKG_INFO_OVERHEAD = 15
    private const val SIGNATURE_SIZE = 34

    fun forUid(uid: Int): ByteArray? {
        if (uid == Process.SYSTEM_UID) {
            return encode(listOf(Pkg("AndroidSystem", 1L)), emptyList())
        }
        val names = Packages.packagesForUid(uid)
        if (names.isEmpty()) return null
        val userId = Packages.userIdOf(uid)
        val packages = ArrayList<Pkg>(names.size)
        var firstSignatures: Array<android.content.pm.Signature>? = null
        for (name in names) {
            val info = Packages.packageInfoWithSigners(name, userId) ?: continue
            packages.add(Pkg(name, versionCodeOf(info)))
            if (firstSignatures == null) {
                @Suppress("DEPRECATION")
                firstSignatures = info.signatures
            }
        }
        if (packages.isEmpty()) return null
        val digests = ArrayList<ByteArray>()
        val sha = MessageDigest.getInstance("SHA-256")
        for (sig in firstSignatures ?: emptyArray()) {
            sha.reset()
            digests.add(sha.digest(sig.toByteArray()))
        }
        return encode(packages, digests)
    }

    private fun encode(packages: List<Pkg>, digests: List<ByteArray>): ByteArray? {
        var estimated = GENERAL_OVERHEAD
        val pkgInfos = ASN1EncodableVector()
        for (pkg in packages) {
            estimated += PKG_INFO_OVERHEAD + pkg.name.length
            if (estimated > MAX_ENCODED) break
            pkgInfos.add(
                DERSequence(
                    ASN1EncodableVector().apply {
                        add(DEROctetString(pkg.name.toByteArray(Charsets.UTF_8)))
                        add(ASN1Integer(pkg.version))
                    }
                )
            )
        }
        if (pkgInfos.size() == 0) return null
        val digestVec = ASN1EncodableVector()
        for (digest in digests) {
            estimated += SIGNATURE_SIZE
            if (estimated > MAX_ENCODED) break
            digestVec.add(DEROctetString(digest))
        }
        return DERSequence(
            ASN1EncodableVector().apply {
                add(DERSet(pkgInfos))
                add(DERSet(digestVec))
            }
        ).encoded
    }

    private fun versionCodeOf(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode
        else @Suppress("DEPRECATION") info.versionCode.toLong()

    private data class Pkg(val name: String, val version: Long)
}
