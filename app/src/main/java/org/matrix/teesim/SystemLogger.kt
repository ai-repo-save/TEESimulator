package org.matrix.teesim

import android.util.Log

/**
 * Centralised logging with a single tag, so logcat is easy to filter.
 *
 * Every line carries the daemon's subsystem token as its first word, matching what the native
 * emitter (common/log_context.cpp) stamps on the interceptor's and the TA's lines: `km`, `km/hook`,
 * `ks1`, `inj`, `ctl`, `ta/…` and, from here, `dmn`. One tag with a subsystem in the message rather
 * than one tag per subsystem, because the collector's kept-tag list (logcat/logcat.cpp) is compiled
 * into a library that has to be reloaded to change, and the WebUI filters on it.
 *
 * There is no verbosity dial. A system property would be world-readable, so a device under test
 * would carry one naming this module; a config key would leave DEBUG/VERBOSE lines out of the file
 * unless someone raised it in advance, when a debugging log exists to already contain the lines
 * that turn out to matter. A level only TAGS a line, for the WebUI's display filter to act on. The
 * only volume control is the native emitter's rate limiter, which drops repeats, never a category.
 */
object SystemLogger {
    private const val TAG = "TEESimulator"
    private const val SUB = "dmn "

    fun verbose(message: String) {
        Log.v(TAG, SUB + message)
    }

    fun debug(message: String) {
        Log.d(TAG, SUB + message)
    }

    fun info(message: String) {
        Log.i(TAG, SUB + message)
    }

    fun warning(message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.w(TAG, SUB + message, throwable) else Log.w(TAG, SUB + message)
    }

    fun error(message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.e(TAG, SUB + message, throwable) else Log.e(TAG, SUB + message)
    }
}

/** Lowercase hex, used for logging digests. */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
