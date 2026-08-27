# Thin Nim wrapper (bindings/c/antech_kdf.h).

import std/[os, strutils]

const packageVersion* = "0.1.0"
const GraphCombinedFrontier* = 3'u32

type
  AntechError* = object of CatchableError
  Config* = object
    memoryKib*: uint32
    saltLength*: uint32
    blockSize*: uint32
    fanIn*: uint32
    graph*: uint32
    outputLength*: uint32
  CConfig {.importc: "AntechConfig", header: "antech_kdf.h".} = object
    memory_kib: uint32
    salt_length: uint32
    block_size: uint32
    fan_in: uint32
    graph: uint32
    output_length: uint32

proc antech_version(): cstring {.importc, header: "antech_kdf.h".}
proc antech_free(p: cstring) {.importc, header: "antech_kdf.h".}
proc antech_config_default(outCfg: ptr CConfig): cint {.importc, header: "antech_kdf.h".}
proc antech_hash_bytes(password: ptr uint8; passwordLen: csize_t; outHash: ptr cstring): cint {.
  importc, header: "antech_kdf.h".}
proc antech_hash_with_config_bytes(password: ptr uint8; passwordLen: csize_t;
    config: ptr CConfig; outHash: ptr cstring): cint {.importc, header: "antech_kdf.h".}
proc antech_verify_bytes(password: ptr uint8; passwordLen: csize_t;
    encodedHash: cstring): cint {.importc, header: "antech_kdf.h".}
proc antech_needs_rehash(encodedHash: cstring; outNeeds: ptr cint): cint {.
  importc, header: "antech_kdf.h".}

proc raiseStatus(st: cint) =
  if st == 0: return
  let msg = case st
    of -1: "invalid input"
    of -2: "invalid hash"
    of -4: "invalid config"
    else: "internal error (" & $st & ")"
  raise newException(AntechError, msg)

proc take(p: cstring): string =
  if p.isNil: raise newException(AntechError, "null string")
  result = $p
  antech_free(p)

proc findLibrary*: string =
  let env = getEnv("ANTECH_KDF_LIB")
  if env.len > 0 and fileExists(env): return env
  let root = currentSourcePath.parentDir.parentDir.parentDir
  let names =
    when defined(windows): @["antech_kdf.dll", "antech_kdf_ffi.dll"]
    elif defined(macosx): @["libantech_kdf.dylib", "libantech_kdf_ffi.dylib"]
    else: @["libantech_kdf.so", "libantech_kdf_ffi.so"]
  let dirs = @[
    env,
    root / "sdk" / "native",
    root / "target" / "release",
    root / "target" / "debug",
  ]
  for d in dirs:
    if d.len == 0: continue
    for n in names:
      let p = d / n
      if fileExists(p): return p
  raise newException(AntechError,
    "native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB")

# Ensure linker finds the cdylib when compiling examples.
{.passL: "-L" & (currentSourcePath.parentDir.parentDir.parentDir / "sdk" / "native").}
{.passL: "-L" & (currentSourcePath.parentDir.parentDir.parentDir / "target" / "release").}
{.passL: "-lantech_kdf".}
{.passC: "-I" & (currentSourcePath.parentDir.parentDir / "c").}

proc version*: string =
  let v = antech_version()
  if v.isNil: packageVersion else: $v

proc configDefault*: Config =
  var c: CConfig
  raiseStatus(antech_config_default(addr c))
  Config(
    memoryKib: c.memory_kib,
    saltLength: c.salt_length,
    blockSize: c.block_size,
    fanIn: c.fan_in,
    graph: c.graph,
    outputLength: c.output_length,
  )

proc toC(cfg: Config): CConfig =
  CConfig(
    memory_kib: cfg.memoryKib,
    salt_length: cfg.saltLength,
    block_size: cfg.blockSize,
    fan_in: cfg.fanIn,
    graph: cfg.graph,
    output_length: cfg.outputLength,
  )

proc hash*(password: string): string =
  var outHash: cstring
  raiseStatus(antech_hash_bytes(
    cast[ptr uint8](password.cstring), csize_t(password.len), addr outHash))
  take(outHash)

proc hashWithConfig*(password: string; config: Config): string =
  var c = config.toC()
  var outHash: cstring
  raiseStatus(antech_hash_with_config_bytes(
    cast[ptr uint8](password.cstring), csize_t(password.len), addr c, addr outHash))
  take(outHash)

proc verify*(password, encodedHash: string): bool =
  let st = antech_verify_bytes(
    cast[ptr uint8](password.cstring), csize_t(password.len), encodedHash.cstring)
  if st == 0: return true
  if st == 1: return false
  raiseStatus(st)

proc needsRehash*(encodedHash: string): bool =
  var needs: cint
  raiseStatus(antech_needs_rehash(encodedHash.cstring, addr needs))
  needs != 0
