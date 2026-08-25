#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
cargo build -p antech-kdf-ffi --release
OUT="$ROOT/sdk/native"
mkdir -p "$OUT"
shopt -s nullglob
for f in target/release/libantech_kdf_ffi.* target/release/antech_kdf_ffi.dll target/release/antech_kdf_ffi.dylib target/release/antech_kdf_ffi.so; do
  [ -f "$f" ] || continue
  cp -f "$f" "$OUT/"
done
# Normalize common names for loaders
if [[ -f "$OUT/antech_kdf_ffi.dll" ]]; then cp -f "$OUT/antech_kdf_ffi.dll" "$OUT/antech_kdf.dll" || true; fi
if [[ -f "$OUT/libantech_kdf_ffi.so" ]]; then cp -f "$OUT/libantech_kdf_ffi.so" "$OUT/libantech_kdf.so" || true; fi
if [[ -f "$OUT/libantech_kdf_ffi.dylib" ]]; then cp -f "$OUT/libantech_kdf_ffi.dylib" "$OUT/libantech_kdf.dylib" || true; fi
cp -f "$ROOT/bindings/c/antech_kdf.h" "$OUT/"
echo "Native artifacts in $OUT"
ls -la "$OUT"
