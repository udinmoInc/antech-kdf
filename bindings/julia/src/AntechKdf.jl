"""Thin Julia ccall wrapper (bindings/c/antech_kdf.h)."""
module AntechKdf

export Config, version, hash, hash_with_config, verify, needs_rehash, config_default

const PACKAGE_VERSION = "0.1.0"
const GRAPH_COMBINED_FRONTIER = UInt32(3)

struct Config
    memory_kib::UInt32
    salt_length::UInt32
    block_size::UInt32
    fan_in::UInt32
    graph::UInt32
    output_length::UInt32
end

mutable struct CConfig
    memory_kib::UInt32
    salt_length::UInt32
    block_size::UInt32
    fan_in::UInt32
    graph::UInt32
    output_length::UInt32
end

function find_library()::String
    env = get(ENV, "ANTECH_KDF_LIB", "")
    if !isempty(env) && isfile(env)
        return env
    end
    root = normpath(joinpath(@__DIR__, "..", ".."))
    names = Sys.iswindows() ? ["antech_kdf.dll", "antech_kdf_ffi.dll"] :
            Sys.isapple() ? ["libantech_kdf.dylib", "libantech_kdf_ffi.dylib"] :
            ["libantech_kdf.so", "libantech_kdf_ffi.so"]
    dirs = filter(!isempty, [
        env,
        joinpath(root, "sdk", "native"),
        joinpath(root, "target", "release"),
        joinpath(root, "target", "debug"),
        joinpath(@__DIR__, "native"),
    ])
    for d in dirs
        for n in names
            p = joinpath(d, n)
            isfile(p) && return p
        end
    end
    error("native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB")
end

const LIB = Ref{String}("")

function lib()
    if isempty(LIB[])
        LIB[] = find_library()
    end
    return LIB[]
end

function raise!(st::Cint)
    st == 0 && return
    msg = st == -1 ? "invalid input" :
          st == -2 ? "invalid hash" :
          st == -4 ? "invalid config" :
          "internal error ($st)"
    error(msg)
end

function take(ptr::Ptr{Cchar})::String
    ptr == C_NULL && error("null string")
    s = unsafe_string(ptr)
    ccall((:antech_free, lib()), Cvoid, (Ptr{Cchar},), ptr)
    return s
end

function version()::String
    p = ccall((:antech_version, lib()), Ptr{Cchar}, ())
    return p == C_NULL ? PACKAGE_VERSION : unsafe_string(p)
end

function config_default()::Config
    c = Ref(CConfig(0, 0, 0, 0, 0, 0))
    raise!(ccall((:antech_config_default, lib()), Cint, (Ref{CConfig},), c))
    v = c[]
    return Config(v.memory_kib, v.salt_length, v.block_size, v.fan_in, v.graph, v.output_length)
end

function hash(password::AbstractString)::String
    pw = String(password)
    out = Ref{Ptr{Cchar}}(C_NULL)
    raise!(ccall((:antech_hash_bytes, lib()), Cint,
        (Ptr{UInt8}, Csize_t, Ref{Ptr{Cchar}}),
        pointer(pw), sizeof(pw), out))
    return take(out[])
end

function hash_with_config(password::AbstractString, config::Config)::String
    pw = String(password)
    c = Ref(CConfig(config.memory_kib, config.salt_length, config.block_size,
                    config.fan_in, config.graph, config.output_length))
    out = Ref{Ptr{Cchar}}(C_NULL)
    raise!(ccall((:antech_hash_with_config_bytes, lib()), Cint,
        (Ptr{UInt8}, Csize_t, Ref{CConfig}, Ref{Ptr{Cchar}}),
        pointer(pw), sizeof(pw), c, out))
    return take(out[])
end

function verify(password::AbstractString, encoded_hash::AbstractString)::Bool
    pw = String(password)
    enc = String(encoded_hash)
    st = ccall((:antech_verify_bytes, lib()), Cint,
        (Ptr{UInt8}, Csize_t, Cstring),
        pointer(pw), sizeof(pw), enc)
    st == 0 && return true
    st == 1 && return false
    raise!(st)
end

function needs_rehash(encoded_hash::AbstractString)::Bool
    enc = String(encoded_hash)
    out = Ref{Cint}(0)
    raise!(ccall((:antech_needs_rehash, lib()), Cint, (Cstring, Ref{Cint}), enc, out))
    return out[] != 0
end

end # module
