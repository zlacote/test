#!/bin/bash
# Build the Ayana test APK without Gradle.
# Needs: ANDROID_HOME (platform >= 35, build-tools), an NDK
# (ANDROID_NDK_LATEST_HOME or ANDROID_NDK_HOME), a JDK, and the Debian rootfs
# at build/assets/rootfs.tar. Output: build/ayana-test.apk
set -euo pipefail
cd "$(dirname "$0")/.."

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
NDK="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-}}"
[ -d "$SDK" ] || { echo "no Android SDK"; exit 1; }
[ -d "$NDK" ] || { echo "no Android NDK"; exit 1; }
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -n 1)
PLAT=""
for p in $(ls -d "$SDK"/platforms/android-* | sort -V); do
  n="${p##*android-}"; n="${n%%[!0-9]*}"
  [ -n "$n" ] && [ "$n" -ge 35 ] && PLAT="$p"
done
[ -n "$PLAT" ] || { echo "no platform >= 35"; exit 1; }
echo "build-tools: $BT"; echo "platform: $PLAT"; echo "ndk: $NDK"

OUT=build
LIBDIR="$OUT/apk/lib/arm64-v8a"
rm -rf "$OUT/apk" "$OUT/classes" "$OUT/dex"
mkdir -p "$LIBDIR" "$OUT/classes" "$OUT/dex" "$OUT/assets"
[ -f "$OUT/assets/rootfs.tar" ] || { echo "missing $OUT/assets/rootfs.tar"; exit 1; }
cp android/assets/apptest.sh "$OUT/assets/"

CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
TGT="--target=aarch64-linux-android29"
PAGE="-Wl,-z,max-page-size=16384"
"$CC" $TGT -O2 -fPIE -pie $PAGE -o "$LIBDIR/libayanaprobe.so" probe/probe.c
"$CC" $TGT -O2 -fPIE -pie $PAGE -o "$LIBDIR/libayanatrue.so" android/native/true.c
"$CC" $TGT -static -nostdlib -fno-pie -no-pie -ffreestanding -fno-stack-protector \
  -mno-outline-atomics -O2 $PAGE -Wl,--image-base=0x10000000 \
  -o "$LIBDIR/libayanarun.so" launcher/ayana-run.c
file "$LIBDIR"/* || true

"$BT/aapt2" link -o "$OUT/base.apk" -I "$PLAT/android.jar" \
  --manifest android/AndroidManifest.xml -A "$OUT/assets" \
  --min-sdk-version 29 --target-sdk-version 35 \
  --version-code "${GITHUB_RUN_NUMBER:-1}" --version-name "0.${GITHUB_RUN_NUMBER:-1}"

javac -source 11 -target 11 -encoding UTF-8 -Xlint:-options \
  -classpath "$PLAT/android.jar" -d "$OUT/classes" $(find android/src -name '*.java')
"$BT/d8" --release --min-api 29 --lib "$PLAT/android.jar" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

(cd "$OUT/dex" && zip -q ../base.apk classes.dex)
(cd "$OUT/apk" && zip -q -r ../base.apk lib)
"$BT/zipalign" -f -p 4 "$OUT/base.apk" "$OUT/aligned.apk"
"$BT/apksigner" sign --ks android/test-only.keystore --ks-pass pass:ayanatest \
  --out "$OUT/ayana-test.apk" "$OUT/aligned.apk"
"$BT/apksigner" verify "$OUT/ayana-test.apk"
ls -la "$OUT/ayana-test.apk"
