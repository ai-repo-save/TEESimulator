// KeyMint names for the log: tags, the enums their values hold, and parameter lists rendered as
// `name=value` text. The tables come from the KeyMint AIDL via scripts/gen-km-names.py.
#ifndef TEESIM_KM_NAMES_H
#define TEESIM_KM_NAMES_H

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "teesim_km.h"

// A tag's lower_snake name ("purpose", "attestation_challenge"), or nullptr for a tag the AIDL
// does not define.
const char *KmTagName(uint32_t tag);

// A parameter list as `{name=value ...}`: enums by name, a repeated tag's values joined with `|`,
// dates as UTC, a BOOL tag as its bare name, printable bytes as a quoted string and other bytes as
// hex (the length and a prefix when long). Tags keep the order of their first appearance.
std::string KmDescribeParams(const KmParam *params, size_t n);

#endif  // TEESIM_KM_NAMES_H
