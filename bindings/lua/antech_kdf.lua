-- Thin LuaJIT FFI wrapper (bindings/c/antech_kdf.h).

local ffi = require("ffi")

ffi.cdef[[
typedef struct AntechConfig {
  uint32_t memory_kib;
  uint32_t salt_length;
  uint32_t block_size;
  uint32_t fan_in;
  uint32_t graph;
  uint32_t output_length;
} AntechConfig;

typedef struct AntechRehashPolicy {
  uint32_t minimum_memory_kib;
  uint32_t preferred_memory_kib;
  uint32_t preferred_fan_in;
  uint32_t preferred_output_length;
  uint32_t preferred_secret_required;
  uint32_t preferred_associated_data;
} AntechRehashPolicy;

const char* antech_version(void);
int antech_config_default(AntechConfig* out);
int antech_rehash_policy_default(AntechRehashPolicy* out);
int antech_hash_bytes(const uint8_t* password, size_t password_len, char** out_hash);
int antech_hash_with_config_bytes(const uint8_t* password, size_t password_len, const AntechConfig* config, char** out_hash);
int antech_hash_with_config_and_salt(const uint8_t* password, size_t password_len, const uint8_t* salt, size_t salt_len, const AntechConfig* config, char** out_hash);
int antech_hash_with_inputs_bytes(const uint8_t* password, size_t password_len, const AntechConfig* config, const uint8_t* secret, size_t secret_len, const uint8_t* associated_data, size_t associated_data_len, char** out_hash);
int antech_hash_with_inputs_and_salt(const uint8_t* password, size_t password_len, const uint8_t* salt, size_t salt_len, const AntechConfig* config, const uint8_t* secret, size_t secret_len, const uint8_t* associated_data, size_t associated_data_len, char** out_hash);
int antech_verify_bytes(const uint8_t* password, size_t password_len, const char* encoded_hash);
int antech_verify_with_inputs_bytes(const uint8_t* password, size_t password_len, const char* encoded_hash, const uint8_t* secret, size_t secret_len, const uint8_t* associated_data, size_t associated_data_len);
int antech_needs_rehash(const char* encoded_hash, int* out_needs_rehash);
int antech_needs_rehash_with_policy(const char* encoded_hash, const AntechRehashPolicy* policy, int* out_needs_rehash);
void antech_free(char* ptr);
]]

local M = {
  VERSION = "0.1.0",
  GRAPH_COMBINED_FRONTIER = 3,
}

local lib

local function is_windows()
  return package.config:sub(1, 1) == "\\"
end

local function library_names()
  if is_windows() then
    return { "antech_kdf.dll", "antech_kdf_ffi.dll" }
  end
  local uname = (io.popen and io.popen("uname -s"):read("*l")) or ""
  if uname == "Darwin" then
    return { "libantech_kdf.dylib", "libantech_kdf_ffi.dylib" }
  end
  return { "libantech_kdf.so", "libantech_kdf_ffi.so" }
end

local function file_exists(path)
  local f = io.open(path, "rb")
  if f then f:close() return true end
  return false
end

local function join(...)
  local sep = is_windows() and "\\" or "/"
  return table.concat({ ... }, sep)
end

function M.find_library()
  local env = os.getenv("ANTECH_KDF_LIB")
  if env and file_exists(env) then return env end
  local here = debug.getinfo(1, "S").source:sub(2)
  local root = here:match("^(.*)[/\\]bindings[/\\]lua")
  local dirs = {
    env,
    root and join(root, "sdk", "native") or nil,
    root and join(root, "target", "release") or nil,
    root and join(root, "target", "debug") or nil,
    join("sdk", "native"),
    join("target", "release"),
  }
  for _, d in ipairs(dirs) do
    if d then
      for _, n in ipairs(library_names()) do
        local p = join(d, n)
        if file_exists(p) then return p end
      end
    end
  end
  error("native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB")
end

local function ensure()
  if lib then return lib end
  lib = ffi.load(M.find_library())
  return lib
end

local function raise(st)
  if st == 0 then return end
  local msg = ({
    [-1] = "invalid input",
    [-2] = "invalid hash",
    [-4] = "invalid config",
  })[st] or ("internal error (" .. tostring(st) .. ")")
  error(msg)
end

local function take(out_ptr)
  local p = out_ptr[0]
  if p == nil then error("null string") end
  local s = ffi.string(p)
  ensure().antech_free(p)
  return s
end

-- nil = absent; "" = present empty
local function opt_buf(data)
  if data == nil then return nil, 0 end
  if #data == 0 then
    local buf = ffi.new("uint8_t[1]")
    return buf, 0
  end
  local buf = ffi.new("uint8_t[?]", #data)
  ffi.copy(buf, data, #data)
  return buf, #data
end

local function bytes_buf(data)
  data = data or ""
  if #data == 0 then
    local buf = ffi.new("uint8_t[1]")
    return buf, 0
  end
  local buf = ffi.new("uint8_t[?]", #data)
  ffi.copy(buf, data, #data)
  return buf, #data
end

function M.version()
  local v = ensure().antech_version()
  return v ~= nil and ffi.string(v) or M.VERSION
end

function M.config_default()
  local c = ffi.new("AntechConfig")
  raise(ensure().antech_config_default(c))
  return {
    memory_kib = tonumber(c.memory_kib),
    salt_length = tonumber(c.salt_length),
    block_size = tonumber(c.block_size),
    fan_in = tonumber(c.fan_in),
    graph = tonumber(c.graph),
    output_length = tonumber(c.output_length),
  }
end

local function to_c_config(cfg)
  local c = ffi.new("AntechConfig")
  c.memory_kib = cfg.memory_kib
  c.salt_length = cfg.salt_length
  c.block_size = cfg.block_size
  c.fan_in = cfg.fan_in
  c.graph = cfg.graph
  c.output_length = cfg.output_length
  return c
end

function M.hash(password)
  local pw, len = bytes_buf(password)
  local out = ffi.new("char*[1]")
  raise(ensure().antech_hash_bytes(pw, len, out))
  return take(out)
end

function M.hash_with_config(password, config)
  local pw, len = bytes_buf(password)
  local out = ffi.new("char*[1]")
  raise(ensure().antech_hash_with_config_bytes(pw, len, to_c_config(config), out))
  return take(out)
end

function M.hash_with_config_and_salt(password, salt, config)
  local pw, pw_len = bytes_buf(password)
  local s, s_len = bytes_buf(salt)
  local out = ffi.new("char*[1]")
  raise(ensure().antech_hash_with_config_and_salt(pw, pw_len, s, s_len, to_c_config(config), out))
  return take(out)
end

function M.hash_with_inputs(password, config, secret, associated_data)
  local pw, pw_len = bytes_buf(password)
  local sec, sec_len = opt_buf(secret)
  local ad, ad_len = opt_buf(associated_data)
  local out = ffi.new("char*[1]")
  raise(ensure().antech_hash_with_inputs_bytes(
    pw, pw_len, to_c_config(config), sec, sec_len, ad, ad_len, out))
  return take(out)
end

function M.verify(password, encoded_hash)
  local pw, len = bytes_buf(password)
  local st = ensure().antech_verify_bytes(pw, len, encoded_hash)
  if st == 0 then return true end
  if st == 1 then return false end
  raise(st)
end

function M.verify_with_inputs(password, encoded_hash, secret, associated_data)
  local pw, len = bytes_buf(password)
  local sec, sec_len = opt_buf(secret)
  local ad, ad_len = opt_buf(associated_data)
  local st = ensure().antech_verify_with_inputs_bytes(
    pw, len, encoded_hash, sec, sec_len, ad, ad_len)
  if st == 0 then return true end
  if st == 1 then return false end
  raise(st)
end

function M.needs_rehash(encoded_hash)
  local out = ffi.new("int[1]")
  raise(ensure().antech_needs_rehash(encoded_hash, out))
  return out[0] ~= 0
end

return M
