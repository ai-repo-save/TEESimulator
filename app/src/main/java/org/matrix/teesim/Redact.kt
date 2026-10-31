package org.matrix.teesim

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Turning device identifiers into stable, non-reversible tokens, for the log and for anything the
 * user exports.
 *
 * A user attaching a log to a public issue must not publish their IMEI or serial. Yet an IMEI
 * replaced by `***` makes "is the value the profile attests the same as the device's real one"
 * unanswerable, which bug reports here often turn on. So the value is replaced by a *keyed digest*
 * — `~a3f91c2e/15` — which compares equal to itself and to nothing else. Two lines carrying the
 * same device value still match; the value does not leave the device; and because the key is
 * per-install, the token is not comparable across devices or against a precomputed IMEI table.
 *
 * What is deliberately NOT redacted:
 * - `bootKey` / `bootHash`. These are the values the module *spoofs*. They are in the keybox, they
 *   are the first thing to check in any attestation report, and they identify a keybox rather than
 *   a person.
 * - Package names, by default. They are load-bearing for triage: "which app asked for this key" is
 *   most of what these logs are for. [mapPackages] can hash them too when a user asks.
 *
 * The honest framing for a user is "this strips the identifiers we know about", not "this file is
 * safe to publish".
 */
object Redact {

    /** Where the per-install salt lives, inside the 0700 data dir. */
    private val keyFile = File(Const.DATA_DIR, "redact.key")

    private const val SALT_BYTES = 32

    @Volatile private var salt: ByteArray? = null

    /**
     * The salt, created on first use. A failure to persist it is not fatal: an in-memory salt still
     * redacts correctly for this boot, it merely stops tokens comparing across restarts.
     */
    private fun salt(): ByteArray {
        salt?.let {
            return it
        }
        synchronized(this) {
            salt?.let {
                return it
            }
            val existing = runCatching {
                if (keyFile.isFile) keyFile.readBytes() else null
            }
                .getOrNull()
            val value =
                if (existing != null && existing.size == SALT_BYTES) existing
                else
                    ByteArray(SALT_BYTES).also { fresh ->
                        SecureRandom().nextBytes(fresh)
                        runCatching {
                            keyFile.parentFile?.mkdirs()
                            keyFile.writeBytes(fresh)
                            keyFile.setReadable(false, false)
                            keyFile.setReadable(true, true)
                            keyFile.setWritable(false, false)
                            keyFile.setWritable(true, true)
                        }
                            .onFailure {
                                SystemLogger.warning(
                                    "Redact: cannot persist the salt; tokens will not " +
                                        "compare across restarts",
                                    it,
                                )
                            }
                    }
            salt = value
            return value
        }
    }

    /**
     * The salt, base64, for the config push: the interceptor tokenizes the identifiers it logs with
     * the same salt and the same algorithm as [token], so one value reads the same everywhere.
     */
    fun saltBase64(): String = java.util.Base64.getEncoder().encodeToString(salt())

    /**
     * A stable token for one identifier: `~<8 hex>/<length>`. The length is kept because it is
     * itself diagnostic (a 15-digit IMEI against a 14-digit one) and reveals nothing.
     */
    fun token(value: String): String {
        if (value.isEmpty()) return ""
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt())
        md.update(value.toByteArray(Charsets.UTF_8))
        val digest = md.digest()
        val hex = StringBuilder(8)
        for (i in 0 until 4) hex.append("%02x".format(digest[i]))
        return "~$hex/${value.length}"
    }

    /** [token], or `''` for a blank value, ready to drop into a quoted log field. */
    fun quoted(value: String): String = if (value.isBlank()) "''" else "'${token(value)}'"

    /**
     * The device values to strip from exported text, learned from the harvest. Anything here is
     * replaced by its token wherever it appears, so a value that leaked into a line this class has
     * never seen is still caught on the way out.
     */
    @Volatile private var known: List<String> = emptyList()

    /** Record the identifiers this device actually has, so [text] can find them anywhere. */
    fun learn(values: Collection<String>) {
        // Longest first, so a value that contains another is replaced whole.
        known = values.filter { it.length >= 6 }.distinct().sortedByDescending { it.length }
    }

    private val BARE_IMEI = Regex("(?<![0-9A-Za-z])[0-9]{15}(?![0-9A-Za-z])")
    private val SECURE_USER_ID = Regex("(SecureUserId|secureUserId)[=:( ]+(-?[0-9]{6,})")
    // The vendored kmr-common uses file!(), so the build machine's absolute source path rides along
    // in the TA's warning lines; this reduces it to the file name.
    private val BUILD_PATH = Regex("/[A-Za-z0-9_./+-]*/(third_party|rust)/[A-Za-z0-9_./+-]+\\.rs")

    /**
     * A redacted copy of `input`, for anything that leaves the device.
     *
     * Applied in three layers: the identifiers this device is known to have, then the shapes that
     * are identifiers wherever they occur, then absolute build paths. When [mapPackages] is set,
     * package-looking names are mapped to `app#<8 hex>` consistently as well.
     */
    fun text(input: String, mapPackages: Boolean = false): String {
        var out = input
        for (value in known) {
            if (value.isNotEmpty() && out.contains(value)) out = out.replace(value, token(value))
        }
        out = BARE_IMEI.replace(out) { token(it.value) }
        out = SECURE_USER_ID.replace(out) { "${it.groupValues[1]}=${token(it.groupValues[2])}" }
        out = BUILD_PATH.replace(out) { "<build>/${it.value.substringAfterLast('/')}" }
        if (mapPackages)
            out =
                PACKAGE.replace(out) {
                    "app#${token(it.value).substringAfter('~').substringBefore('/')}"
                }
        return out
    }

    // Three or more dot-separated lowercase-ish segments: the shape of an Android package name.
    // Off by default; see the class comment.
    private val PACKAGE = Regex("\\b[a-z][a-z0-9_]*(\\.[a-z0-9_]+){2,}\\b")
}
