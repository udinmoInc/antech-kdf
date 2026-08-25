# Build antech-kdf-ffi release library into sdk/native for language bindings.
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root
cargo build -p antech-kdf-ffi --release
$Out = Join-Path $Root "sdk\native"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$candidates = @(
  "target\release\antech_kdf_ffi.dll",
  "target\release\antech_kdf_ffi.dll.lib",
  "target\release\libantech_kdf_ffi.so",
  "target\release\libantech_kdf_ffi.dylib",
  "target\release\antech_kdf_ffi.lib"
)
foreach ($c in $candidates) {
  $p = Join-Path $Root $c
  if (Test-Path $p) { Copy-Item -Force $p $Out }
}
$dll = Join-Path $Out "antech_kdf_ffi.dll"
if (Test-Path $dll) { Copy-Item -Force $dll (Join-Path $Out "antech_kdf.dll") }
Copy-Item -Force (Join-Path $Root "bindings\c\antech_kdf.h") $Out
Write-Host "Native artifacts in $Out"
Get-ChildItem $Out
