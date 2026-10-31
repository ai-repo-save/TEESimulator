// The logging support every target shares: the per-thread "who is this call for" prefix and the
// emitter every line goes through. KeyMint names (errors, tags, enums) are in km_names.cpp.
//
// The routers stamp the context at each hooked entry point (LogContext in logging.hpp); the Rust TA
// reads the same thread's value through teesim_log_context() so its lines are attributed
// identically. Kept in its own translation unit because the injector, the KeyMint interceptor, the
// keystore1 interceptor and the TA all need one definition of it.

#include <android/log.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <cstdint>
#include <string>

namespace {
// A std::string rather than a borrowed pointer: the caller's context is built per request and must
// stay readable for the whole call, including from Rust, after the builder has gone out of scope.
thread_local std::string g_ctx;
}  // namespace

extern "C" const char* teesim_log_context(void) { return g_ctx.c_str(); }

// A short serial naming ONE request, minted at each hooked entry point and carried on every line
// that request produces, in both languages.
//
// A thread id is not enough to correlate by: keystore2 reuses its binder threads, so one thread
// serves several apps' requests within milliseconds. Sixteen bits printed as four hex digits is
// enough to tell apart everything in flight at once while staying short enough to sit on every line;
// it wraps, and is meant to be read within a window of a few seconds, not to be unique for a boot.
extern "C" unsigned teesim_log_new_rid(void) {
  static std::atomic<unsigned> next{0};
  return next.fetch_add(1, std::memory_order_relaxed) & 0xffffu;
}

extern "C" void teesim_log_set_context(const char* ctx) { g_ctx.assign(ctx ? ctx : ""); }

// --- The emitter -------------------------------------------------------------
//
// Every log line in the injector, the KeyMint interceptor, the keystore1 interceptor and the Rust TA
// goes through this one function, so every level shares one line shape: subsystem, request
// context, message.
//
// It does three cheap things and nothing else: stamp the subsystem, stamp the thread's request
// context, and rate-limit a D/V flood. One stack buffer, no heap, no lock, no
// exceptions — teesim_keystore is built -fno-exceptions, so an allocation failure on this path would
// abort the Android 10/11 keystore daemon outright.

namespace {

// Milliseconds on a coarse monotonic clock. CLOCK_MONOTONIC_COARSE reads the kernel's cached time
// through the vDSO with no syscall, which is all a token bucket needs.
int64_t NowMonoMs() {
  struct timespec ts {};
  clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
  return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

// --- D/V flood backstop ------------------------------------------------------
//
// The injector's per-symbol tracing and the reference TA's per-request opcode trace reach logd, the
// collector's ring and a rotating file on disk. A log flood inside an observed process can stall
// it, so D and V lines are budgeted per subsystem. I, W, E and F are never rate-limited and never
// dropped: no evidence, and no line written just before a crash, may be lost to this.
constexpr int32_t kRatePerSec = 200;
constexpr int32_t kBurst = 400;

struct Bucket {
  std::atomic<int32_t> tokens{kBurst};
  std::atomic<int64_t> last_ms{0};
  std::atomic<uint32_t> dropped{0};
  std::atomic<int64_t> drop_since_ms{0};
};

// Hashed rather than keyed: the C++ subsystems are compile-time literals, but the Rust side derives
// its own from the record's module path, so there is no fixed set to index. A collision only means
// two subsystems share a budget, which for a flood backstop is not worth a map and a lock.
Bucket g_buckets[16];

uint32_t HashSub(const char* s) {
  uint32_t h = 2166136261u;
  for (; s != nullptr && *s != '\0'; ++s) {
    h ^= static_cast<unsigned char>(*s);
    h *= 16777619u;
  }
  return h;
}

bool RateOk(const char* sub) {
  Bucket& b = g_buckets[HashSub(sub) & 15u];
  const int64_t now = NowMonoMs();
  int64_t last = b.last_ms.load(std::memory_order_relaxed);
  if (now > last) {
    const int64_t add = (now - last) * kRatePerSec / 1000;
    if (add > 0 && b.last_ms.compare_exchange_weak(last, now, std::memory_order_relaxed)) {
      int32_t t = b.tokens.load(std::memory_order_relaxed) + static_cast<int32_t>(
                      add > kBurst ? kBurst : add);
      b.tokens.store(t > kBurst ? kBurst : t, std::memory_order_relaxed);
      const uint32_t missed = b.dropped.exchange(0, std::memory_order_relaxed);
      if (missed != 0) {
        // Reported straight to liblog rather than through teesim_log, which would re-enter here.
        const int64_t since = b.drop_since_ms.load(std::memory_order_relaxed);
        __android_log_print(ANDROID_LOG_WARN, "TEESimulator",
                            "%s RateOk: rate limit dropped %u D/V line(s) over %lldms",
                            sub != nullptr ? sub : "", missed,
                            static_cast<long long>(since != 0 ? now - since : 0));
      }
    }
  }
  if (b.tokens.fetch_sub(1, std::memory_order_relaxed) <= 0) {
    b.tokens.fetch_add(1, std::memory_order_relaxed);
    if (b.dropped.fetch_add(1, std::memory_order_relaxed) == 0) {
      b.drop_since_ms.store(now, std::memory_order_relaxed);
    }
    return false;
  }
  return true;
}

}  // namespace

// There is no level floor, and deliberately no setting that could add one. A level (LOGV..LOGF)
// tags what a line is, for the WebUI's display filter to act on; it never decides whether the line
// is written. A debugging log exists to already contain the lines that turn out to matter, and a
// system property to control it would be world-readable, naming this module on the device. The
// only volume control is the rate limiter above, which drops repeats, never a whole category.
extern "C" void teesim_log(int prio, const char* sub, const char* fmt, ...) {
  if (prio < ANDROID_LOG_INFO && !RateOk(sub)) return;
  // Sized against the longest line any emitter produces (a harvested KeyDescription dump, around
  // 700 bytes) with room to spare, and well under liblog's own ~4068-byte limit. A line
  // that would overrun is marked rather than silently cut.
  char buf[2048];
  const char* ctx = teesim_log_context();
  int n = snprintf(buf, sizeof(buf), "%s%s%s", sub != nullptr ? sub : "",
                   (sub != nullptr && *sub != '\0') ? " " : "", ctx);
  if (n < 0) n = 0;
  if (static_cast<size_t>(n) < sizeof(buf)) {
    va_list ap;
    va_start(ap, fmt);
    const int m = vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
    va_end(ap);
    if (m > 0 && static_cast<size_t>(n + m) >= sizeof(buf)) {
      memcpy(buf + sizeof(buf) - 4, "\xe2\x80\xa6", 4);
    }
  }
  __android_log_write(prio, "TEESimulator", buf);
}
