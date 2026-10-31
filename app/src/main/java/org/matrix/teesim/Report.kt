package org.matrix.teesim

import android.os.Build
import java.io.File
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * The session header and the bug-report bundle.
 *
 * [header] writes the module version, device and Android release into the log itself, once, at
 * INFO: a log usually reaches an issue as pasted text, and the collector's timestamps carry no year
 * and no UTC offset (`localtime_r`, `"%02d-%02d %02d:%02d:%02d.%03ld"`).
 *
 * [writeBundle] is what the WebUI's Save button reaches. It packs the whole on-disk rotation rather
 * than the WebUI's 4000-line client ring, and the daemon writes the file itself, so no log content
 * passes through the WebView.
 */
object Report {

    /** teesim.log plus the rolled parts, oldest first — the order a reader wants. */
    private const val LOG_PART_MAX = 4

    /**
     * The session header: everything a maintainer needs before the first log line means anything.
     *
     * The bracket-and-count is AOSP's own watchdog convention, and it earns its place here: it
     * makes a truncated paste detectable, which a header without a terminator does not.
     */
    fun header(): List<String> {
        val lines = ArrayList<String>()
        fun add(key: String, value: String) = lines.add("$key $value")

        add(
            "module      ",
            "version=${Updater.currentVersion().ifBlank { "?" }} abi=${abi()} " +
                "sdk=${Build.VERSION.SDK_INT} release=${Build.VERSION.RELEASE}",
        )
        add("boot id     ", bootId())
        add("boot when   ", bootWhen())
        add(
            "boot device ",
            "fp=${Build.FINGERPRINT} manufacturer=${Build.MANUFACTURER} model=${Build.MODEL}",
        )
        return lines
    }

    /**
     * The kernel's per-boot UUID: the same value the log collector keys its per-boot rotation on,
     * so a pasted header names the boot its lines belong to.
     */
    private fun bootId(): String =
        runCatching { File("/proc/sys/kernel/random/boot_id").readText().trim() }
            .getOrNull()
            ?.ifBlank { null } ?: "?"

    /** Write the header into the log, framed so a partial paste is obvious. */
    fun logHeader() {
        val body = header()
        SystemLogger.info(
            "Report: === TEESimulator session begin — paste everything down to \"session end\" ==="
        )
        body.forEach { SystemLogger.info("Report: $it") }
        SystemLogger.info("Report: === TEESimulator session end (${body.size} lines) ===")
    }

    /**
     * Stream a redacted bug-report zip to [out].
     *
     * Everything is redacted on the way past ([Redact.text]); nothing is buffered whole, so a 10 MB
     * rotation costs a stream rather than a heap allocation in the root daemon.
     */
    fun writeBundle(out: OutputStream, redact: Boolean, mapPackages: Boolean) {
        ZipOutputStream(out).use { zip ->
            fun entry(name: String, body: String) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(
                    (if (redact) Redact.text(body, mapPackages) else body).toByteArray(
                        Charsets.UTF_8
                    )
                )
                zip.closeEntry()
            }

            entry(
                "header.txt",
                (listOf("=== TEESimulator report ===") + header()).joinToString("\n") + "\n",
            )

            // The rotation, oldest first, each part its own entry so a reader can open just the
            // tail.
            val parts =
                (LOG_PART_MAX downTo 1).map { File(Const.logDir, "teesim.$it.log") } +
                    File(Const.logDir, "teesim.log")
            for (f in parts.filter { it.isFile }) {
                zip.putNextEntry(ZipEntry("log/${f.name}"))
                f.bufferedReader(Charsets.UTF_8).useLines { seq ->
                    for (line in seq) {
                        val text = if (redact) Redact.text(line, mapPackages) else line
                        zip.write(text.toByteArray(Charsets.UTF_8))
                        zip.write('\n'.code)
                    }
                }
                zip.closeEntry()
            }

            // The configuration the log was produced under. Without it, half the questions a log
            // raises ("which profile, which mode, which patch levels") need a round trip to ask.
            for (f in listOf(Const.configFile, Const.harvestedFile, Const.overridesFile)) {
                if (!f.isFile) continue
                entry(
                    f.name,
                    runCatching { f.readText() }.getOrElse { "<unreadable: ${it.message}>" },
                )
            }

            entry("props.txt", propsSnapshot())
            entry("modules.txt", modulesSnapshot())
        }
    }

    /**
     * An allowlist, not a dump: the properties that bear on attestation and RKP. A full `getprop`
     * carries far more about the user than a report needs, and the serial is redacted like every
     * other identifier.
     */
    private fun propsSnapshot(): String {
        val keys =
            listOf(
                "ro.build.fingerprint",
                "ro.build.version.sdk",
                "ro.build.version.release",
                "ro.build.version.security_patch",
                "ro.vendor.build.security_patch",
                "ro.boot.verifiedbootstate",
                "ro.boot.veritymode",
                "ro.boot.vbmeta.digest",
                "ro.product.brand",
                "ro.product.device",
                "ro.product.model",
                "ro.product.manufacturer",
                "ro.serialno",
                "remote_provisioning.enable_rkpd",
                "remote_provisioning.tee.rkp_only",
                "remote_provisioning.strongbox.rkp_only",
            )
        return keys.joinToString("\n") { "$it=${DeviceProps.prop(it, "")}" } + "\n"
    }

    /** Other installed modules: a frequent cause, and invisible from our own log. */
    private fun modulesSnapshot(): String {
        val root = File("/data/adb/modules")
        val dirs = root.listFiles()?.filter { it.isDirectory }?.sortedBy { it.name } ?: emptyList()
        if (dirs.isEmpty()) return "<no modules directory>\n"
        return dirs.joinToString("\n") { dir ->
            val prop = File(dir, "module.prop")
            val version =
                runCatching {
                    prop.readLines().firstOrNull { it.startsWith("version=") }?.substringAfter("=")
                }
                    .getOrNull() ?: "?"
            val disabled = if (File(dir, "disable").exists()) " (disabled)" else ""
            "${dir.name} $version$disabled"
        } + "\n"
    }

    private fun abi(): String = Build.SUPPORTED_ABIS.firstOrNull() ?: "?"

    /**
     * The "boot when" field. Early in boot the RTC may not have synced yet, and an unsynced clock
     * printed as an RFC-3339 timestamp would read as fact. No boot can have finished before the
     * running module was placed on disk ([installFloorMs]), so a wall-clock reading earlier than
     * that is certainly wrong and is reported as unsynced instead.
     */
    private fun bootWhen(): String {
        val now = System.currentTimeMillis()
        val floor = installFloorMs()
        val suffix = "(log timestamps below are LOCAL time, with no year and no offset)"
        return if (floor > 0 && now < floor) {
            "device clock not yet synced (reads ${isoNow(now)}, before this build's own install " +
                "time); real boot time unknown until a later line shows a plausible date $suffix"
        } else {
            "${isoNow(now)} $suffix"
        }
    }

    private fun isoNow(epochMs: Long): String {
        val f = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", java.util.Locale.US)
        return f.format(java.util.Date(epochMs))
    }

    /**
     * When the currently-running module was placed on this device, or 0 when neither copy of its
     * module.prop can be stat'd. Same two paths and the same active-before-staged precedence
     * [Updater] already reads versionCode/version from, so this tracks the copy actually executing
     * rather than one staged for the next boot.
     */
    private fun installFloorMs(): Long {
        for (p in
            listOf(
                "/data/adb/modules/teesim/module.prop",
                "/data/adb/modules_update/teesim/module.prop",
            )) {
            val m = File(p).lastModified()
            if (m > 0) return m
        }
        return 0
    }
}
