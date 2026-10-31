#!/usr/bin/env bash
# Host-side conformance tests for the KeyMint TA.
#
# The tests under rust/teesim-km/tests drive the TA directly: fixed test keybox, fixed challenge and
# application id, pinned attestation version. No device, no interceptor, no keystore — the TA is the
# binary that produces the attestation record, so running it on the host is enough to pin what it
# must emit.
#
# The BoringSSL backend links against libcrypto, so this builds BoringSSL for the host once into
# third_party/boringssl/build-host (cmake + ninja) and points openssl-sys at it. Pass extra arguments
# through to cargo test (e.g. `./rust/test-host.sh conformance`).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BORINGSSL="${BORINGSSL:-$ROOT/third_party/boringssl}"
# Keep the host build out of the submodule working tree, which the Android build reads headers from.
BUILD="${HOST_BSSL_BUILD:-$HERE/.cache/boringssl-host}"

if [ ! -f "$BUILD/libcrypto.a" ]; then
  echo "test-host: building host BoringSSL in $BUILD" >&2
  cmake -GNinja -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=0 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 "$BORINGSSL" >/dev/null
  cmake --build "$BUILD" --target crypto >/dev/null
fi

# The patches adapt the vendored kmr-ta to Cargo; rust/build.sh applies the same series for the
# Android build.
mapfile -t PATCHES < <(printf '%s\n' "$HERE"/patches/*.patch | LC_ALL=C sort)
for PATCH in "${PATCHES[@]}"; do
  if git -C "$ROOT/third_party/keymint" apply -p1 --reverse --check "$PATCH" 2>/dev/null; then
    :
  else
    git -C "$ROOT/third_party/keymint" apply -p1 "$PATCH"
  fi
done

export OPENSSL_NO_VENDOR=1
export OPENSSL_INCLUDE_DIR="$BORINGSSL/include"
export OPENSSL_LIB_DIR="$BUILD"
export OPENSSL_STATIC=1
export OPENSSL_LIBS=crypto
# BoringSSL is C++: the static archive needs the C++ runtime at link time.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-lstdc++"

cd "$HERE"
exec cargo test --tests "$@"
