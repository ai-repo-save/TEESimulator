#include "redact.h"

#include <stdio.h>

#include <mutex>
#include <vector>

// BoringSSL's one-shot digest. Both interceptors link a libcrypto that provides it: keymint the
// host's, through its stub; keystore the bundled static BoringSSL.
extern "C" uint8_t *SHA256(const uint8_t *data, size_t len, uint8_t *out);

namespace {
std::mutex g_mu;
std::vector<uint8_t> g_salt;
}  // namespace

void RedactSetSalt(const uint8_t *salt, size_t len) {
  std::lock_guard<std::mutex> lk(g_mu);
  g_salt.assign(salt, salt + len);
}

std::string RedactToken(const uint8_t *value, size_t len) {
  char buf[40];
  std::vector<uint8_t> input;
  {
    std::lock_guard<std::mutex> lk(g_mu);
    input = g_salt;
  }
  if (input.empty()) {
    snprintf(buf, sizeof(buf), "~?/%zu", len);
    return buf;
  }
  if (value != nullptr) input.insert(input.end(), value, value + len);
  uint8_t digest[32];
  SHA256(input.data(), input.size(), digest);
  snprintf(buf, sizeof(buf), "~%02x%02x%02x%02x/%zu", digest[0], digest[1], digest[2], digest[3],
           len);
  return buf;
}
