// Identifier tokens for the log, computed exactly as the daemon's Redact.token: the first four bytes
// of SHA-256(salt || value) as hex, then the value's length, as `~a3f91c2e/15`. The salt is the
// daemon's per-install one, delivered with each config push, so a value tokenizes identically in
// the interceptor's lines and the daemon's.
#ifndef TEESIM_REDACT_H
#define TEESIM_REDACT_H

#include <stddef.h>
#include <stdint.h>

#include <string>

// Install the salt from a config push. Thread-safe; replaces any earlier salt.
void RedactSetSalt(const uint8_t *salt, size_t len);

// The token for `value`. Before a salt arrives the digest reads `?`: the value is still withheld.
std::string RedactToken(const uint8_t *value, size_t len);

#endif  // TEESIM_REDACT_H
