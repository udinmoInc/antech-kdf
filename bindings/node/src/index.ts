import fs from "fs";
import path from "path";
import koffi from "koffi";

export const VERSION = "0.1.0";

export const GRAPH_COMBINED_FRONTIER = 3;

export class AntechError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AntechError";
  }
}

const AntechConfigT = koffi.struct("AntechConfig", {
  memory_kib: "uint32",
  salt_length: "uint32",
  block_size: "uint32",
  fan_in: "uint32",
  graph: "uint32",
  output_length: "uint32",
});

const AntechRehashPolicyT = koffi.struct("AntechRehashPolicy", {
  minimum_memory_kib: "uint32",
  preferred_memory_kib: "uint32",
  preferred_fan_in: "uint32",
  preferred_output_length: "uint32",
  preferred_secret_required: "uint32",
  preferred_associated_data: "uint32",
});

function nativeCandidates(): string[] {
  const env = process.env.ANTECH_KDF_LIB;
  // dist/ → bindings/node → bindings → repo root
  const root = path.resolve(__dirname, "..", "..", "..");
  const names =
    process.platform === "win32"
      ? ["antech_kdf.dll", "antech_kdf_ffi.dll"]
      : process.platform === "darwin"
        ? ["libantech_kdf.dylib", "libantech_kdf_ffi.dylib"]
        : ["libantech_kdf.so", "libantech_kdf_ffi.so"];
  const dirs = [
    env,
    path.join(root, "sdk", "native"),
    path.join(root, "target", "release"),
    path.join(root, "target", "debug"),
    path.join(__dirname, "..", "native"),
  ].filter(Boolean) as string[];
  const out: string[] = [];
  for (const d of dirs) {
    for (const n of names) out.push(path.join(d, n));
  }
  return out;
}

function loadLib() {
  for (const p of nativeCandidates()) {
    if (fs.existsSync(p)) {
      return koffi.load(p);
    }
  }
  throw new AntechError(
    "native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB"
  );
}

const lib = loadLib();
const antech_version = lib.func("antech_version", "str", []);
const antech_free = lib.func("antech_free", "void", ["void *"]);
const antech_config_default = lib.func("antech_config_default", "int", [
  koffi.out(koffi.pointer(AntechConfigT)),
]);
const antech_rehash_policy_default = lib.func("antech_rehash_policy_default", "int", [
  koffi.out(koffi.pointer(AntechRehashPolicyT)),
]);
const antech_hash_bytes = lib.func("antech_hash_bytes", "int", [
  "void *",
  "size_t",
  koffi.out("void **"),
]);
const antech_hash_with_config_bytes = lib.func("antech_hash_with_config_bytes", "int", [
  "void *",
  "size_t",
  koffi.pointer(AntechConfigT),
  koffi.out("void **"),
]);
const antech_hash_with_config_and_salt = lib.func("antech_hash_with_config_and_salt", "int", [
  "void *",
  "size_t",
  "void *",
  "size_t",
  koffi.pointer(AntechConfigT),
  koffi.out("void **"),
]);
const antech_hash_with_inputs_bytes = lib.func("antech_hash_with_inputs_bytes", "int", [
  "void *",
  "size_t",
  koffi.pointer(AntechConfigT),
  "void *",
  "size_t",
  "void *",
  "size_t",
  koffi.out("void **"),
]);
const antech_hash_with_inputs_and_salt = lib.func("antech_hash_with_inputs_and_salt", "int", [
  "void *",
  "size_t",
  "void *",
  "size_t",
  koffi.pointer(AntechConfigT),
  "void *",
  "size_t",
  "void *",
  "size_t",
  koffi.out("void **"),
]);
const antech_verify_bytes = lib.func("antech_verify_bytes", "int", [
  "void *",
  "size_t",
  "str",
]);
const antech_verify_with_inputs_bytes = lib.func("antech_verify_with_inputs_bytes", "int", [
  "void *",
  "size_t",
  "str",
  "void *",
  "size_t",
  "void *",
  "size_t",
]);
const antech_needs_rehash = lib.func("antech_needs_rehash", "int", [
  "str",
  koffi.out("int *"),
]);
const antech_needs_rehash_with_policy = lib.func("antech_needs_rehash_with_policy", "int", [
  "str",
  koffi.pointer(AntechRehashPolicyT),
  koffi.out("int *"),
]);

function raise(st: number): void {
  if (st === 0) return;
  if (st === -1) throw new AntechError("invalid input");
  if (st === -2) throw new AntechError("invalid hash");
  if (st === -4) throw new AntechError("invalid config");
  throw new AntechError(`internal error (${st})`);
}

function takeString(ptr: any): string {
  // koffi.decode(ptr, "str") can AV on Windows when POD structs are registered
  // (koffi 2.16.x). Read a bounded NUL-terminated byte view instead.
  const bytes = koffi.decode(ptr, koffi.array("uint8", 4096)) as number[];
  antech_free(ptr);
  const end = bytes.indexOf(0);
  const slice = end >= 0 ? bytes.slice(0, end) : bytes;
  return Buffer.from(slice).toString("utf8");
}

function asBuf(password: string | Buffer | Uint8Array): Buffer {
  if (typeof password === "string") return Buffer.from(password, "utf8");
  return Buffer.from(password);
}

export interface Config {
  memory_kib: number;
  salt_length: number;
  block_size: number;
  fan_in: number;
  graph: number;
  output_length: number;
}

export interface RehashPolicy {
  minimum_memory_kib: number;
  preferred_memory_kib: number;
  preferred_fan_in: number;
  preferred_output_length: number;
  preferred_secret_required?: number;
  preferred_associated_data?: number;
}

/** undefined/null = absent; empty Buffer = present-but-empty. See antech_kdf.h. */
export type OptionalBytes = Buffer | Uint8Array | null | undefined;

function optBuf(data: OptionalBytes): { ptr: Buffer | null; len: number } {
  if (data === null || data === undefined) {
    return { ptr: null, len: 0 };
  }
  const buf = Buffer.from(data);
  // Empty present: non-null zero-length needs a scratch buffer for FFI.
  if (buf.length === 0) {
    return { ptr: Buffer.alloc(1), len: 0 };
  }
  return { ptr: buf, len: buf.length };
}

export function defaultConfig(): Config {
  const c: any = {};
  raise(antech_config_default(c));
  return c as Config;
}

export function defaultRehashPolicy(): RehashPolicy {
  const p: any = {};
  raise(antech_rehash_policy_default(p));
  return p as RehashPolicy;
}

export function version(): string {
  return antech_version();
}

export function hash(password: string | Buffer | Uint8Array): string {
  const buf = asBuf(password);
  const out: any = [null];
  raise(antech_hash_bytes(buf, buf.length, out));
  return takeString(out[0]);
}

export function hashWithConfig(
  password: string | Buffer | Uint8Array,
  config: Config
): string {
  const buf = asBuf(password);
  const out: any = [null];
  raise(antech_hash_with_config_bytes(buf, buf.length, config, out));
  return takeString(out[0]);
}

export function hashWithConfigAndSalt(
  password: string | Buffer | Uint8Array,
  salt: Buffer | Uint8Array,
  config: Config
): string {
  const buf = asBuf(password);
  const s = Buffer.from(salt);
  const out: any = [null];
  raise(antech_hash_with_config_and_salt(buf, buf.length, s, s.length, config, out));
  return takeString(out[0]);
}

export function hashWithInputs(
  password: string | Buffer | Uint8Array,
  config: Config,
  options?: { secret?: OptionalBytes; associatedData?: OptionalBytes }
): string {
  const buf = asBuf(password);
  const sec = optBuf(options?.secret);
  const ad = optBuf(options?.associatedData);
  const out: any = [null];
  raise(
    antech_hash_with_inputs_bytes(
      buf,
      buf.length,
      config,
      sec.ptr,
      sec.len,
      ad.ptr,
      ad.len,
      out
    )
  );
  return takeString(out[0]);
}

export function hashWithInputsAndSalt(
  password: string | Buffer | Uint8Array,
  salt: Buffer | Uint8Array,
  config: Config,
  options?: { secret?: OptionalBytes; associatedData?: OptionalBytes }
): string {
  const buf = asBuf(password);
  const s = Buffer.from(salt);
  const sec = optBuf(options?.secret);
  const ad = optBuf(options?.associatedData);
  const out: any = [null];
  raise(
    antech_hash_with_inputs_and_salt(
      buf,
      buf.length,
      s,
      s.length,
      config,
      sec.ptr,
      sec.len,
      ad.ptr,
      ad.len,
      out
    )
  );
  return takeString(out[0]);
}

export function verify(
  password: string | Buffer | Uint8Array,
  encodedHash: string
): boolean {
  const buf = asBuf(password);
  const st = antech_verify_bytes(buf, buf.length, encodedHash);
  if (st === 0) return true;
  if (st === 1) return false;
  raise(st);
  return false;
}

export function verifyWithInputs(
  password: string | Buffer | Uint8Array,
  encodedHash: string,
  options?: { secret?: OptionalBytes; associatedData?: OptionalBytes }
): boolean {
  const buf = asBuf(password);
  const sec = optBuf(options?.secret);
  const ad = optBuf(options?.associatedData);
  const st = antech_verify_with_inputs_bytes(
    buf,
    buf.length,
    encodedHash,
    sec.ptr,
    sec.len,
    ad.ptr,
    ad.len
  );
  if (st === 0) return true;
  if (st === 1) return false;
  raise(st);
  return false;
}

export function needsRehash(encodedHash: string): boolean {
  const out: any = [0];
  raise(antech_needs_rehash(encodedHash, out));
  return out[0] !== 0;
}

export function needsRehashWithPolicy(
  encodedHash: string,
  policy: RehashPolicy
): boolean {
  const out: any = [0];
  raise(antech_needs_rehash_with_policy(encodedHash, policy, out));
  return out[0] !== 0;
}
