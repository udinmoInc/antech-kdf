/// Thin Dart FFI wrapper (bindings/c/antech_kdf.h).
library antech_kdf;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

const String packageVersion = '0.1.0';
const int graphCombinedFrontier = 3;

class AntechException implements Exception {
  AntechException(this.message);
  final String message;
  @override
  String toString() => 'AntechException: $message';
}

final class Config {
  Config({
    this.memoryKib = 16384,
    this.saltLength = 16,
    this.blockSize = 32,
    this.fanIn = 2,
    this.graph = graphCombinedFrontier,
    this.outputLength = 32,
  });

  int memoryKib;
  int saltLength;
  int blockSize;
  int fanIn;
  int graph;
  int outputLength;

  static Config defaults() {
    final c = calloc<_AntechConfig>();
    try {
      _raise(_lib.antechConfigDefault(c));
      return Config(
        memoryKib: c.ref.memoryKib,
        saltLength: c.ref.saltLength,
        blockSize: c.ref.blockSize,
        fanIn: c.ref.fanIn,
        graph: c.ref.graph,
        outputLength: c.ref.outputLength,
      );
    } finally {
      calloc.free(c);
    }
  }

  Pointer<_AntechConfig> toNative() {
    final c = calloc<_AntechConfig>();
    c.ref
      ..memoryKib = memoryKib
      ..saltLength = saltLength
      ..blockSize = blockSize
      ..fanIn = fanIn
      ..graph = graph
      ..outputLength = outputLength;
    return c;
  }
}

final class RehashPolicy {
  RehashPolicy({
    this.minimumMemoryKib = 16384,
    this.preferredMemoryKib = 16384,
    this.preferredFanIn = 2,
    this.preferredOutputLength = 32,
    this.preferredSecretRequired = false,
    this.preferredAssociatedData = false,
  });

  int minimumMemoryKib;
  int preferredMemoryKib;
  int preferredFanIn;
  int preferredOutputLength;
  bool preferredSecretRequired;
  bool preferredAssociatedData;

  static RehashPolicy defaults() {
    final p = calloc<_AntechRehashPolicy>();
    try {
      _raise(_lib.antechRehashPolicyDefault(p));
      return RehashPolicy(
        minimumMemoryKib: p.ref.minimumMemoryKib,
        preferredMemoryKib: p.ref.preferredMemoryKib,
        preferredFanIn: p.ref.preferredFanIn,
        preferredOutputLength: p.ref.preferredOutputLength,
        preferredSecretRequired: p.ref.preferredSecretRequired != 0,
        preferredAssociatedData: p.ref.preferredAssociatedData != 0,
      );
    } finally {
      calloc.free(p);
    }
  }

  Pointer<_AntechRehashPolicy> toNative() {
    final p = calloc<_AntechRehashPolicy>();
    p.ref
      ..minimumMemoryKib = minimumMemoryKib
      ..preferredMemoryKib = preferredMemoryKib
      ..preferredFanIn = preferredFanIn
      ..preferredOutputLength = preferredOutputLength
      ..preferredSecretRequired = preferredSecretRequired ? 1 : 0
      ..preferredAssociatedData = preferredAssociatedData ? 1 : 0;
    return p;
  }
}

final class _AntechConfig extends Struct {
  @Uint32()
  external int memoryKib;
  @Uint32()
  external int saltLength;
  @Uint32()
  external int blockSize;
  @Uint32()
  external int fanIn;
  @Uint32()
  external int graph;
  @Uint32()
  external int outputLength;
}

final class _AntechRehashPolicy extends Struct {
  @Uint32()
  external int minimumMemoryKib;
  @Uint32()
  external int preferredMemoryKib;
  @Uint32()
  external int preferredFanIn;
  @Uint32()
  external int preferredOutputLength;
  @Uint32()
  external int preferredSecretRequired;
  @Uint32()
  external int preferredAssociatedData;
}

typedef _VersionNative = Pointer<Utf8> Function();
typedef _VersionDart = Pointer<Utf8> Function();
typedef _ConfigDefaultNative = Int32 Function(Pointer<_AntechConfig>);
typedef _ConfigDefaultDart = int Function(Pointer<_AntechConfig>);
typedef _RehashDefaultNative = Int32 Function(Pointer<_AntechRehashPolicy>);
typedef _RehashDefaultDart = int Function(Pointer<_AntechRehashPolicy>);
typedef _HashBytesNative = Int32 Function(
    Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>);
typedef _HashBytesDart = int Function(
    Pointer<Uint8>, int, Pointer<Pointer<Utf8>>);
typedef _HashConfigNative = Int32 Function(
    Pointer<Uint8>, Size, Pointer<_AntechConfig>, Pointer<Pointer<Utf8>>);
typedef _HashConfigDart = int Function(
    Pointer<Uint8>, int, Pointer<_AntechConfig>, Pointer<Pointer<Utf8>>);
typedef _HashSaltNative = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>,
    Size, Pointer<_AntechConfig>, Pointer<Pointer<Utf8>>);
typedef _HashSaltDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<_AntechConfig>, Pointer<Pointer<Utf8>>);
typedef _HashInputsNative = Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<_AntechConfig>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Pointer<Utf8>>);
typedef _HashInputsDart = int Function(
    Pointer<Uint8>,
    int,
    Pointer<_AntechConfig>,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Pointer<Utf8>>);
typedef _HashInputsSaltNative = Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<_AntechConfig>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Pointer<Utf8>>);
typedef _HashInputsSaltDart = int Function(
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<_AntechConfig>,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Pointer<Utf8>>);
typedef _VerifyNative = Int32 Function(Pointer<Uint8>, Size, Pointer<Utf8>);
typedef _VerifyDart = int Function(Pointer<Uint8>, int, Pointer<Utf8>);
typedef _VerifyInputsNative = Int32 Function(Pointer<Uint8>, Size, Pointer<Utf8>,
    Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _VerifyInputsDart = int Function(Pointer<Uint8>, int, Pointer<Utf8>,
    Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _NeedsRehashNative = Int32 Function(Pointer<Utf8>, Pointer<Int32>);
typedef _NeedsRehashDart = int Function(Pointer<Utf8>, Pointer<Int32>);
typedef _NeedsPolicyNative = Int32 Function(
    Pointer<Utf8>, Pointer<_AntechRehashPolicy>, Pointer<Int32>);
typedef _NeedsPolicyDart = int Function(
    Pointer<Utf8>, Pointer<_AntechRehashPolicy>, Pointer<Int32>);
typedef _FreeNative = Void Function(Pointer<Utf8>);
typedef _FreeDart = void Function(Pointer<Utf8>);

class _Lib {
  _Lib(DynamicLibrary d)
      : antechVersion =
            d.lookupFunction<_VersionNative, _VersionDart>('antech_version'),
        antechConfigDefault = d.lookupFunction<_ConfigDefaultNative,
            _ConfigDefaultDart>('antech_config_default'),
        antechRehashPolicyDefault = d.lookupFunction<_RehashDefaultNative,
            _RehashDefaultDart>('antech_rehash_policy_default'),
        antechHashBytes =
            d.lookupFunction<_HashBytesNative, _HashBytesDart>('antech_hash_bytes'),
        antechHashWithConfigBytes = d.lookupFunction<_HashConfigNative,
            _HashConfigDart>('antech_hash_with_config_bytes'),
        antechHashWithConfigAndSalt = d.lookupFunction<_HashSaltNative,
            _HashSaltDart>('antech_hash_with_config_and_salt'),
        antechHashWithInputsBytes = d.lookupFunction<_HashInputsNative,
            _HashInputsDart>('antech_hash_with_inputs_bytes'),
        antechHashWithInputsAndSalt = d.lookupFunction<_HashInputsSaltNative,
            _HashInputsSaltDart>('antech_hash_with_inputs_and_salt'),
        antechVerifyBytes =
            d.lookupFunction<_VerifyNative, _VerifyDart>('antech_verify_bytes'),
        antechVerifyWithInputsBytes = d.lookupFunction<_VerifyInputsNative,
            _VerifyInputsDart>('antech_verify_with_inputs_bytes'),
        antechNeedsRehash = d.lookupFunction<_NeedsRehashNative,
            _NeedsRehashDart>('antech_needs_rehash'),
        antechNeedsRehashWithPolicy = d.lookupFunction<_NeedsPolicyNative,
            _NeedsPolicyDart>('antech_needs_rehash_with_policy'),
        antechFree = d.lookupFunction<_FreeNative, _FreeDart>('antech_free');

  final _VersionDart antechVersion;
  final _ConfigDefaultDart antechConfigDefault;
  final _RehashDefaultDart antechRehashPolicyDefault;
  final _HashBytesDart antechHashBytes;
  final _HashConfigDart antechHashWithConfigBytes;
  final _HashSaltDart antechHashWithConfigAndSalt;
  final _HashInputsDart antechHashWithInputsBytes;
  final _HashInputsSaltDart antechHashWithInputsAndSalt;
  final _VerifyDart antechVerifyBytes;
  final _VerifyInputsDart antechVerifyWithInputsBytes;
  final _NeedsRehashDart antechNeedsRehash;
  final _NeedsPolicyDart antechNeedsRehashWithPolicy;
  final _FreeDart antechFree;
}

final _Lib _lib = _Lib(DynamicLibrary.open(_findLibrary()));

String _findLibrary() {
  final env = Platform.environment['ANTECH_KDF_LIB'];
  final root = Directory.current.path;
  // Walk up from script package: bindings/dart → repo root
  final candidates = <String>[];
  if (env != null && env.isNotEmpty) {
    if (File(env).existsSync()) return env;
    candidates.add(env);
  }
  final names = Platform.isWindows
      ? ['antech_kdf.dll', 'antech_kdf_ffi.dll']
      : Platform.isMacOS
          ? ['libantech_kdf.dylib', 'libantech_kdf_ffi.dylib']
          : ['libantech_kdf.so', 'libantech_kdf_ffi.so'];
  for (final sub in [
    'sdk/native',
    'target/release',
    'target/debug',
    'bindings/dart/native',
  ]) {
    candidates.add('$root${Platform.pathSeparator}$sub');
  }
  // Also try relative to package path if run from bindings/dart
  final pkgRoot = File(Platform.script.toFilePath()).parent.parent.path;
  final repoRoot = Directory(pkgRoot).parent.parent.path;
  for (final base in [pkgRoot, repoRoot, root]) {
    for (final sub in ['sdk/native', 'target/release', 'target/debug', 'native']) {
      for (final n in names) {
        final p = '$base${Platform.pathSeparator}$sub${Platform.pathSeparator}$n';
        if (File(p).existsSync()) return p;
      }
    }
  }
  for (final d in candidates) {
    for (final n in names) {
      final p = '$d${Platform.pathSeparator}$n';
      if (File(p).existsSync()) return p;
    }
  }
  throw AntechException(
      'native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB');
}

void _raise(int st) {
  if (st == 0) return;
  final msg = switch (st) {
    -1 => 'invalid input',
    -2 => 'invalid hash',
    -4 => 'invalid config',
    _ => 'internal error ($st)',
  };
  throw AntechException(msg);
}

String _take(Pointer<Pointer<Utf8>> out) {
  final p = out.value;
  if (p == nullptr) throw AntechException('null string');
  final s = p.toDartString();
  _lib.antechFree(p);
  return s;
}

bool _asVerified(int st) {
  if (st == 0) return true;
  if (st == 1) return false;
  _raise(st);
  return false;
}

/// null = absent; empty list = present empty.
({Pointer<Uint8> ptr, int len, Pointer<Uint8>? keep}) _optBytes(Uint8List? data) {
  if (data == null) return (ptr: nullptr, len: 0, keep: null);
  if (data.isEmpty) {
    final scratch = calloc<Uint8>();
    return (ptr: scratch, len: 0, keep: scratch);
  }
  final buf = calloc<Uint8>(data.length);
  buf.asTypedList(data.length).setAll(0, data);
  return (ptr: buf, len: data.length, keep: buf);
}

({Pointer<Uint8> ptr, int len, Pointer<Uint8>? keep}) _bytes(Uint8List data) {
  if (data.isEmpty) return (ptr: nullptr, len: 0, keep: null);
  final buf = calloc<Uint8>(data.length);
  buf.asTypedList(data.length).setAll(0, data);
  return (ptr: buf, len: data.length, keep: buf);
}

Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));

String version() {
  final p = _lib.antechVersion();
  return p == nullptr ? packageVersion : p.toDartString();
}

String hash(String password) => hashBytes(_utf8(password));

String hashBytes(Uint8List password) {
  final pw = _bytes(password);
  final out = calloc<Pointer<Utf8>>();
  try {
    _raise(_lib.antechHashBytes(pw.ptr, pw.len, out));
    return _take(out);
  } finally {
    if (pw.keep != null) calloc.free(pw.keep!);
    calloc.free(out);
  }
}

String hashWithConfig(String password, Config config) =>
    hashWithConfigBytes(_utf8(password), config);

String hashWithConfigBytes(Uint8List password, Config config) {
  final pw = _bytes(password);
  final cfg = config.toNative();
  final out = calloc<Pointer<Utf8>>();
  try {
    _raise(_lib.antechHashWithConfigBytes(pw.ptr, pw.len, cfg, out));
    return _take(out);
  } finally {
    if (pw.keep != null) calloc.free(pw.keep!);
    calloc.free(cfg);
    calloc.free(out);
  }
}

String hashWithConfigAndSalt(Uint8List password, Uint8List salt, Config config) {
  final pw = _bytes(password);
  final s = _bytes(salt);
  final cfg = config.toNative();
  final out = calloc<Pointer<Utf8>>();
  try {
    _raise(_lib.antechHashWithConfigAndSalt(
        pw.ptr, pw.len, s.ptr, s.len, cfg, out));
    return _take(out);
  } finally {
    if (pw.keep != null) calloc.free(pw.keep!);
    if (s.keep != null) calloc.free(s.keep!);
    calloc.free(cfg);
    calloc.free(out);
  }
}

String hashWithInputs(
  Uint8List password,
  Config config, {
  Uint8List? secret,
  Uint8List? associatedData,
}) {
  final pw = _bytes(password);
  final sec = _optBytes(secret);
  final ad = _optBytes(associatedData);
  final cfg = config.toNative();
  final out = calloc<Pointer<Utf8>>();
  try {
    _raise(_lib.antechHashWithInputsBytes(
        pw.ptr, pw.len, cfg, sec.ptr, sec.len, ad.ptr, ad.len, out));
    return _take(out);
  } finally {
    if (pw.keep != null) calloc.free(pw.keep!);
    if (sec.keep != null) calloc.free(sec.keep!);
    if (ad.keep != null) calloc.free(ad.keep!);
    calloc.free(cfg);
    calloc.free(out);
  }
}

String hashWithInputsAndSalt(
  Uint8List password,
  Uint8List salt,
  Config config, {
  Uint8List? secret,
  Uint8List? associatedData,
}) {
  final pw = _bytes(password);
  final s = _bytes(salt);
  final sec = _optBytes(secret);
  final ad = _optBytes(associatedData);
  final cfg = config.toNative();
  final out = calloc<Pointer<Utf8>>();
  try {
    _raise(_lib.antechHashWithInputsAndSalt(pw.ptr, pw.len, s.ptr, s.len, cfg,
        sec.ptr, sec.len, ad.ptr, ad.len, out));
    return _take(out);
  } finally {
    if (pw.keep != null) calloc.free(pw.keep!);
    if (s.keep != null) calloc.free(s.keep!);
    if (sec.keep != null) calloc.free(sec.keep!);
    if (ad.keep != null) calloc.free(ad.keep!);
    calloc.free(cfg);
    calloc.free(out);
  }
}

bool verify(String password, String encodedHash) =>
    verifyBytes(_utf8(password), encodedHash);

bool verifyBytes(Uint8List password, String encodedHash) {
  final pw = _bytes(password);
  final h = encodedHash.toNativeUtf8();
  try {
    return _asVerified(_lib.antechVerifyBytes(pw.ptr, pw.len, h));
  } finally {
    if (pw.keep != null) calloc.free(pw.keep!);
    calloc.free(h);
  }
}

bool verifyWithInputs(
  Uint8List password,
  String encodedHash, {
  Uint8List? secret,
  Uint8List? associatedData,
}) {
  final pw = _bytes(password);
  final sec = _optBytes(secret);
  final ad = _optBytes(associatedData);
  final h = encodedHash.toNativeUtf8();
  try {
    return _asVerified(_lib.antechVerifyWithInputsBytes(
        pw.ptr, pw.len, h, sec.ptr, sec.len, ad.ptr, ad.len));
  } finally {
    if (pw.keep != null) calloc.free(pw.keep!);
    if (sec.keep != null) calloc.free(sec.keep!);
    if (ad.keep != null) calloc.free(ad.keep!);
    calloc.free(h);
  }
}

bool needsRehash(String encodedHash) {
  final h = encodedHash.toNativeUtf8();
  final out = calloc<Int32>();
  try {
    _raise(_lib.antechNeedsRehash(h, out));
    return out.value != 0;
  } finally {
    calloc.free(h);
    calloc.free(out);
  }
}

bool needsRehashWithPolicy(String encodedHash, RehashPolicy policy) {
  final h = encodedHash.toNativeUtf8();
  final p = policy.toNative();
  final out = calloc<Int32>();
  try {
    _raise(_lib.antechNeedsRehashWithPolicy(h, p, out));
    return out.value != 0;
  } finally {
    calloc.free(h);
    calloc.free(p);
    calloc.free(out);
  }
}
