#!/bin/bash
# Build the native executables of the test app into its jniLibs directory.
# They are executables named lib*.so so that the package installer extracts
# them to nativeLibraryDir. Needs an NDK: NDK_HOME, or ANDROID_HOME/ndk/NDK_VERSION,
# or ANDROID_NDK_LATEST_HOME.
set -euo pipefail
cd "$(dirname "$0")/.."

NDK="${NDK_HOME:-}"
[ -z "$NDK" ] && [ -n "${NDK_VERSION:-}" ] && NDK="${ANDROID_HOME:-}/ndk/$NDK_VERSION"
[ -d "$NDK" ] || NDK="${ANDROID_NDK_LATEST_HOME:-}"
[ -d "$NDK" ] || { echo "no NDK found"; exit 1; }
echo "ndk: $NDK"

OUT=android/app/src/main/jniLibs/arm64-v8a
rm -rf "$OUT"
mkdir -p "$OUT"
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
TGT="--target=aarch64-linux-android29"
PAGE="-Wl,-z,max-page-size=16384"

"$CC" $TGT -O2 -fPIE -pie $PAGE -o "$OUT/libayanaprobe.so" probe/probe.c
"$CC" $TGT -O2 -fPIE -pie $PAGE -o "$OUT/libayanatrue.so" android/native/true.c
"$CC" $TGT -static -nostdlib -fno-pie -ffreestanding -fno-stack-protector \
  -mno-outline-atomics -O2 $PAGE -Wl,--image-base=0x10000000 \
  -o "$OUT/libayanarun.so" launcher/ayana-run.c
file "$OUT"/* || true
