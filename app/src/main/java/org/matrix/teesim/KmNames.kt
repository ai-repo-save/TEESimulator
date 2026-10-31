package org.matrix.teesim

import java.time.Instant
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject

/**
 * KeyMint values for log lines, rendered by the same rules as the interceptor's decoder
 * (common/km_names.cpp): names are the AOSP identifiers in lower_snake_case (tags from [KmAidl],
 * fields from the KeyDescription schema), enums print by name, a set joins with `|`, dates print as
 * UTC, printable bytes as a quoted string and other bytes as hex, abbreviated past 32 bytes.
 */
object KmNames {

    private val SECURITY_LEVEL = mapOf(0 to "SW", 1 to "TEE", 2 to "StrongBox")
    private val VERIFIED_BOOT =
        mapOf(0 to "Verified", 1 to "SelfSigned", 2 to "Unverified", 3 to "Failed")

    /** KeyDescription ::= SEQUENCE, in schema order. */
    private val KEY_DESCRIPTION =
        listOf(
            "attestation_version",
            "attestation_security_level",
            "key_mint_version",
            "key_mint_security_level",
            "attestation_challenge",
            "unique_id",
            "software_enforced",
            "hardware_enforced",
        )

    /** RootOfTrust ::= SEQUENCE, in schema order. */
    private val ROOT_OF_TRUST =
        listOf("verified_boot_key", "device_locked", "verified_boot_state", "verified_boot_hash")

    private const val TAG_USER_AUTH_TYPE = 504L
    private const val TAG_ROOT_OF_TRUST = 704L

    fun securityLevel(v: Int): String = SECURITY_LEVEL[v] ?: v.toString()

    fun verifiedBootState(v: Int): String = VERIFIED_BOOT[v] ?: v.toString()

    /** HardwareAuthenticatorType is a bitmask of its members; NONE and ANY are exact values. */
    fun authenticatorType(v: Long): String {
        KmAidl.HARDWARE_AUTHENTICATOR_TYPE[v]?.let {
            return it
        }
        val names = ArrayList<String>()
        var rest = v
        for ((bit, name) in KmAidl.HARDWARE_AUTHENTICATOR_TYPE) {
            if (bit <= 0L || v and bit != bit) continue
            names.add(name)
            rest = rest and bit.inv()
        }
        if (rest != 0L) names.add("0x" + rest.toString(16))
        return names.joinToString("|")
    }

    /** Bytes as the interceptor prints them. */
    fun bytes(b: ByteArray): String =
        when {
            b.isEmpty() -> "\"\""
            b.all { it in 0x20..0x7e } -> "\"${String(b, Charsets.US_ASCII)}\""
            b.size <= 32 -> b.toHex()
            else -> "<${b.size}B ${b.copyOf(8).toHex()}~>"
        }

    /** A KeyDescription as `{attestation_version=400 ... hardware_enforced={...}}`. */
    fun keyDescription(kd: ASN1Sequence): String =
        kd.mapIndexed { i, field ->
                val name = KEY_DESCRIPTION.getOrNull(i) ?: "field_$i"
                val value =
                    when (i) {
                        1,
                        3 -> number(field)?.let { securityLevel(it.toInt()) } ?: plain(field)
                        6,
                        7 -> authorizationList(field)
                        else -> plain(field)
                    }
                "$name=$value"
            }
            .joinToString(" ", prefix = "{", postfix = "}")

    private fun authorizationList(field: ASN1Encodable): String {
        val seq = field.toASN1Primitive() as? ASN1Sequence ?: return plain(field)
        return seq.joinToString(" ", prefix = "{", postfix = "}") { el ->
            val tagged = el.toASN1Primitive() as? ASN1TaggedObject ?: return@joinToString plain(el)
            val tag = tagged.tagNo.toLong()
            val name = KmAidl.TAG[tag] ?: "tag_$tag"
            val value = tagged.baseObject.toASN1Primitive()
            // A BOOL tag is present-or-absent; the schema encodes presence as NULL.
            if (value is ASN1Null) name else "$name=${tagValue(tag, value)}"
        }
    }

    private fun tagValue(tag: Long, value: ASN1Encodable): String {
        val members = (value as? ASN1Set)?.toList() ?: listOf(value)
        return members.joinToString("|") { m ->
            val n = number(m)
            val table = KmAidl.TAG_ENUM[tag]
            when {
                tag == TAG_ROOT_OF_TRUST -> rootOfTrust(m)
                n != null && tag == TAG_USER_AUTH_TYPE -> authenticatorType(n)
                n != null && table != null -> table[n] ?: n.toString()
                n != null && tag in KmAidl.DATE_TAGS -> Instant.ofEpochMilli(n).toString()
                else -> plain(m)
            }
        }
    }

    private fun rootOfTrust(value: ASN1Encodable): String {
        val seq = value.toASN1Primitive() as? ASN1Sequence ?: return plain(value)
        return seq.mapIndexed { i, f ->
                val v =
                    if (i == 2) number(f)?.let { verifiedBootState(it.toInt()) } ?: plain(f)
                    else plain(f)
                "${ROOT_OF_TRUST.getOrNull(i) ?: "field_$i"}=$v"
            }
            .joinToString(" ", prefix = "{", postfix = "}")
    }

    /** Anything the schema gives no meaning to: numbers, booleans, bytes, nested values. */
    private fun plain(value: ASN1Encodable?): String =
        when (val p = value?.toASN1Primitive()) {
            null,
            is ASN1Null -> "NULL"
            is ASN1Integer -> p.value.toString()
            is ASN1Enumerated -> p.value.toString()
            is ASN1Boolean -> p.isTrue.toString()
            is ASN1OctetString -> bytes(p.octets)
            is ASN1Sequence -> p.joinToString(" ", prefix = "{", postfix = "}") { plain(it) }
            is ASN1Set -> p.joinToString("|") { plain(it) }
            is ASN1TaggedObject -> "[${p.tagNo}]${plain(p.baseObject)}"
            else -> p.toString()
        }

    private fun number(el: ASN1Encodable): Long? =
        when (val p = el.toASN1Primitive()) {
            is ASN1Integer -> p.value.toLong()
            is ASN1Enumerated -> p.value.toLong()
            else -> null
        }
}
