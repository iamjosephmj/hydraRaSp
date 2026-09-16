#!/usr/bin/env bash
# Build the RootOfTrust-spoof native Zygisk module. NDK r27+. Research ONLY.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
NDK=${NDK:-$(ls -d "$HOME"/Android/Sdk/ndk/* | sort -V | tail -1)}
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64"; API=${API:-28}
OUT="$HERE/build"; rm -rf "$OUT"; mkdir -p "$OUT/module/zygisk"
for ABI in arm64-v8a:aarch64-linux-android x86_64:x86_64-linux-android; do
  A="${ABI%%:*}"; T="${ABI##*:}"
  "$TC/bin/${T}${API}-clang++" -std=c++17 -O2 -fPIC -shared -fvisibility=hidden -Wall \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -static-libstdc++ \
    -o "$OUT/module/zygisk/$A.so" "$HERE/module.cpp" -llog
done
cp "$HERE/module.prop" "$OUT/module/"
( cd "$OUT/module" && zip -qr "$OUT/di-rot-spoof.zip" . )
echo "packaged: $OUT/di-rot-spoof.zip"
