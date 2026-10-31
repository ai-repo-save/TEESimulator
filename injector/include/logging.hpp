#pragma once

#include <android/log.h>
#include <errno.h>
#include <stdint.h>

// The one logcat tag the whole module speaks under, hardcoded in the emitter rather than taken from
// a macro: the collector's kept-tag list (logcat/logcat.cpp) is compiled into a library that has to
// be reloaded to change, and the WebUI filters on it. What varies per file is LOG_SUB, below.

// --- Request context ---------------------------------------------------------
//
// Every hooked call runs on the binder thread of the app that made it, so "who is this for" is a
// per-thread fact. Each entry point stamps it once (see LogContext below) and every line that thread
// logs carries it until the call returns, so a line is attributable to its app and request without
// relying on its proximity to other lines on interleaved binder threads.
#ifdef __cplusplus
extern "C" {
#endif
// Never null; "" when no request is in scope. Valid until this thread sets a new one.
const char *teesim_log_context(void);
void teesim_log_set_context(const char *ctx);
// The ErrorCode name for a KeyMint status, or "?" for a code outside the AIDL. Never null, so it can
// be passed straight to a %s. Defined alongside the context in common/log_context.cpp.
const char *teesim_km_err_name(int32_t code);

// --- The emitter -------------------------------------------------------------
//
// One function behind every macro below, defined in common/log_context.cpp and linked into all three
// native targets. It prepends the subsystem and the thread's request context, and rate-limits a D/V
// flood. Every level shares one line shape, and none is compiled out or filtered: see the note above
// teesim_log's definition for why there is no level floor.
void teesim_log(int prio, const char *sub, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
// The next request serial, for the entry point that is about to stamp a context. Wraps at 16 bits.
unsigned teesim_log_new_rid(void);
#ifdef __cplusplus
}
#endif

// The subsystem this file speaks for: the first token of every line it logs, and the coarsest filter
// a reader has. Defined per translation unit before this header is included; a file that forgets it
// degrades to an unprefixed line rather than failing to build.
#ifndef LOG_SUB
#define LOG_SUB ""
#endif

#undef LOGV
#undef LOGD
#undef LOGI
#undef LOGW
#undef LOGE
#undef LOGF
#undef PLOGE
#define LOGV(...) teesim_log(ANDROID_LOG_VERBOSE, LOG_SUB, __VA_ARGS__)
#define LOGD(...) teesim_log(ANDROID_LOG_DEBUG, LOG_SUB, __VA_ARGS__)
#define LOGI(...) teesim_log(ANDROID_LOG_INFO, LOG_SUB, __VA_ARGS__)
#define LOGW(...) teesim_log(ANDROID_LOG_WARN, LOG_SUB, __VA_ARGS__)
#define LOGE(...) teesim_log(ANDROID_LOG_ERROR, LOG_SUB, __VA_ARGS__)
#define LOGF(...) teesim_log(ANDROID_LOG_FATAL, LOG_SUB, __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))

#ifdef __cplusplus
#include <string>

// Stamps the caller this thread is serving onto every line it logs, and clears it on the way out.
// Nesting is not expected (one binder call per thread at a time), so the destructor restores the
// context that was in scope on entry rather than blindly clearing it.
class LogContext {
  public:
    explicit LogContext(const std::string &ctx) : saved_(teesim_log_context()) {
        teesim_log_set_context(ctx.c_str());
    }
    ~LogContext() { teesim_log_set_context(saved_.c_str()); }
    LogContext(const LogContext &) = delete;
    LogContext &operator=(const LogContext &) = delete;

  private:
    std::string saved_;
};
#endif
