#!/usr/bin/env bash
# Build the native half into the LSPosed module APK, then build + sign the APK.
# Requires NDK r27+ (set NDK=/path/to/ndk) and the Android SDK build-tools.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/.."
: "${NDK:?set NDK=/path/to/android-ndk-r27c}"
API=${API:-28}
HOST=$(uname | tr '[:upper:]' '[:lower:]')-x86_64
TC="$NDK/toolchains/llvm/prebuilt/$HOST/bin"

mkdir -p "$HERE/src/main/jniLibs/arm64-v8a"
"$TC/aarch64-linux-android${API}-clang++" \
    -std=c++17 -O2 -fPIC -shared -fvisibility=default -Wall -static-libstdc++ \
    -o "$HERE/src/main/jniLibs/arm64-v8a/libfullbypass.so" \
    "$ROOT/native/fullbypass.cpp" -llog

( cd "$HERE" && ../../../gradlew -p . assembleRelease )

BT=${BT:-$HOME/Library/Android/sdk/build-tools/36.1.0}
APK=$(find "$HERE/build/outputs" -name '*-release-unsigned.apk' | head -1)
"$BT/apksigner" sign \
    --ks "$HOME/.android/debug.keystore" --ks-pass pass:android \
    --ks-key-alias androiddebugkey --key-pass pass:android \
    --out "$HERE/build/full-signed.apk" "$APK"
echo "packaged: $HERE/build/full-signed.apk"
