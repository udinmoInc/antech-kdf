# frozen_string_literal: true

require "ffi"
require "rbconfig"

# Thin Ruby FFI wrapper (bindings/c/antech_kdf.h).

module Antech
  VERSION = "0.1.0"
  GRAPH_COMBINED_FRONTIER = 3

  class Error < StandardError; end

  Config = Struct.new(
    :memory_kib, :salt_length, :block_size, :fan_in, :graph, :output_length,
    keyword_init: true
  ) do
    def self.default
      c = Native::AntechConfig.new
      Native.raise!(Native.antech_config_default(c))
      new(
        memory_kib: c[:memory_kib],
        salt_length: c[:salt_length],
        block_size: c[:block_size],
        fan_in: c[:fan_in],
        graph: c[:graph],
        output_length: c[:output_length]
      )
    end

    def to_native
      c = Native::AntechConfig.new
      c[:memory_kib] = memory_kib
      c[:salt_length] = salt_length
      c[:block_size] = block_size
      c[:fan_in] = fan_in
      c[:graph] = graph
      c[:output_length] = output_length
      c
    end
  end

  RehashPolicy = Struct.new(
    :minimum_memory_kib, :preferred_memory_kib, :preferred_fan_in,
    :preferred_output_length, :preferred_secret_required, :preferred_associated_data,
    keyword_init: true
  ) do
    def self.default
      p = Native::AntechRehashPolicy.new
      Native.raise!(Native.antech_rehash_policy_default(p))
      new(
        minimum_memory_kib: p[:minimum_memory_kib],
        preferred_memory_kib: p[:preferred_memory_kib],
        preferred_fan_in: p[:preferred_fan_in],
        preferred_output_length: p[:preferred_output_length],
        preferred_secret_required: p[:preferred_secret_required] != 0,
        preferred_associated_data: p[:preferred_associated_data] != 0
      )
    end

    def to_native
      p = Native::AntechRehashPolicy.new
      p[:minimum_memory_kib] = minimum_memory_kib
      p[:preferred_memory_kib] = preferred_memory_kib
      p[:preferred_fan_in] = preferred_fan_in
      p[:preferred_output_length] = preferred_output_length
      p[:preferred_secret_required] = preferred_secret_required ? 1 : 0
      p[:preferred_associated_data] = preferred_associated_data ? 1 : 0
      p
    end
  end

  module Native
    extend FFI::Library

    class AntechConfig < FFI::Struct
      layout :memory_kib, :uint32,
             :salt_length, :uint32,
             :block_size, :uint32,
             :fan_in, :uint32,
             :graph, :uint32,
             :output_length, :uint32
    end

    class AntechRehashPolicy < FFI::Struct
      layout :minimum_memory_kib, :uint32,
             :preferred_memory_kib, :uint32,
             :preferred_fan_in, :uint32,
             :preferred_output_length, :uint32,
             :preferred_secret_required, :uint32,
             :preferred_associated_data, :uint32
    end

    def self.library_path
      env = ENV["ANTECH_KDF_LIB"]
      root = File.expand_path("../../..", __dir__)
      names =
        case RbConfig::CONFIG["host_os"]
        when /mswin|mingw|cygwin/i then %w[antech_kdf.dll antech_kdf_ffi.dll]
        when /darwin/i then %w[libantech_kdf.dylib libantech_kdf_ffi.dylib]
        else %w[libantech_kdf.so libantech_kdf_ffi.so]
        end
      dirs = [
        (File.file?(env.to_s) ? File.dirname(env) : env),
        File.join(root, "sdk", "native"),
        File.join(root, "target", "release"),
        File.join(root, "target", "debug"),
        File.join(__dir__, "native")
      ].compact.reject(&:empty?)
      return env if env && File.file?(env)

      dirs.each do |d|
        names.each do |n|
          p = File.join(d, n)
          return p if File.file?(p)
        end
      end
      raise Error, "native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB"
    end

    ffi_lib library_path

    attach_function :antech_version, [], :string
    attach_function :antech_free, [:pointer], :void
    attach_function :antech_config_default, [AntechConfig.by_ref], :int
    attach_function :antech_rehash_policy_default, [AntechRehashPolicy.by_ref], :int
    attach_function :antech_hash_bytes, [:pointer, :size_t, :pointer], :int
    attach_function :antech_hash_with_config_bytes, [:pointer, :size_t, AntechConfig.by_ref, :pointer], :int
    attach_function :antech_hash_with_config_and_salt,
                    [:pointer, :size_t, :pointer, :size_t, AntechConfig.by_ref, :pointer], :int
    attach_function :antech_hash_with_inputs_bytes,
                    [:pointer, :size_t, AntechConfig.by_ref, :pointer, :size_t, :pointer, :size_t, :pointer], :int
    attach_function :antech_hash_with_inputs_and_salt,
                    [:pointer, :size_t, :pointer, :size_t, AntechConfig.by_ref, :pointer, :size_t, :pointer, :size_t, :pointer], :int
    attach_function :antech_verify_bytes, [:pointer, :size_t, :string], :int
    attach_function :antech_verify_with_inputs_bytes,
                    [:pointer, :size_t, :string, :pointer, :size_t, :pointer, :size_t], :int
    attach_function :antech_needs_rehash, [:string, :pointer], :int
    attach_function :antech_needs_rehash_with_policy, [:string, AntechRehashPolicy.by_ref, :pointer], :int

    module_function

    def raise!(st)
      return if st == 0

      msg =
        case st
        when -1 then "invalid input"
        when -2 then "invalid hash"
        when -4 then "invalid config"
        else "internal error (#{st})"
        end
      raise Error, msg
    end

    def take(out_ptr)
      p = out_ptr.read_pointer
      raise Error, "null string" if p.null?

      s = p.read_string
      antech_free(p)
      s
    end

    # nil = absent; empty string = present empty.
    def opt_buf(data)
      return [FFI::Pointer::NULL, 0] if data.nil?
      return [FFI::MemoryPointer.new(:uint8, 1), 0] if data.bytesize.zero?

      buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
      buf.put_bytes(0, data)
      [buf, data.bytesize]
    end

    def bytes_buf(data)
      return [FFI::Pointer::NULL, 0] if data.nil? || data.bytesize.zero?

      buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
      buf.put_bytes(0, data)
      [buf, data.bytesize]
    end
  end

  module_function

  def version
    Native.antech_version || VERSION
  end

  def hash(password)
    pw, len = Native.bytes_buf(password.to_s)
    out = FFI::MemoryPointer.new(:pointer)
    Native.raise!(Native.antech_hash_bytes(pw, len, out))
    Native.take(out)
  end

  def hash_with_config(password, config)
    pw, len = Native.bytes_buf(password.to_s)
    out = FFI::MemoryPointer.new(:pointer)
    Native.raise!(Native.antech_hash_with_config_bytes(pw, len, config.to_native, out))
    Native.take(out)
  end

  def hash_with_config_and_salt(password, salt, config)
    pw, pw_len = Native.bytes_buf(password.to_s)
    s, s_len = Native.bytes_buf(salt.to_s)
    out = FFI::MemoryPointer.new(:pointer)
    Native.raise!(Native.antech_hash_with_config_and_salt(pw, pw_len, s, s_len, config.to_native, out))
    Native.take(out)
  end

  def hash_with_inputs(password, config, secret: nil, associated_data: nil)
    pw, pw_len = Native.bytes_buf(password.to_s)
    sec, sec_len = Native.opt_buf(secret)
    ad, ad_len = Native.opt_buf(associated_data)
    out = FFI::MemoryPointer.new(:pointer)
    Native.raise!(Native.antech_hash_with_inputs_bytes(
      pw, pw_len, config.to_native, sec, sec_len, ad, ad_len, out
    ))
    Native.take(out)
  end

  def hash_with_inputs_and_salt(password, salt, config, secret: nil, associated_data: nil)
    pw, pw_len = Native.bytes_buf(password.to_s)
    s, s_len = Native.bytes_buf(salt.to_s)
    sec, sec_len = Native.opt_buf(secret)
    ad, ad_len = Native.opt_buf(associated_data)
    out = FFI::MemoryPointer.new(:pointer)
    Native.raise!(Native.antech_hash_with_inputs_and_salt(
      pw, pw_len, s, s_len, config.to_native, sec, sec_len, ad, ad_len, out
    ))
    Native.take(out)
  end

  def verify(password, encoded_hash)
    pw, len = Native.bytes_buf(password.to_s)
    st = Native.antech_verify_bytes(pw, len, encoded_hash)
    return true if st == 0
    return false if st == 1

    Native.raise!(st)
  end

  def verify_with_inputs(password, encoded_hash, secret: nil, associated_data: nil)
    pw, len = Native.bytes_buf(password.to_s)
    sec, sec_len = Native.opt_buf(secret)
    ad, ad_len = Native.opt_buf(associated_data)
    st = Native.antech_verify_with_inputs_bytes(pw, len, encoded_hash, sec, sec_len, ad, ad_len)
    return true if st == 0
    return false if st == 1

    Native.raise!(st)
  end

  def needs_rehash(encoded_hash)
    out = FFI::MemoryPointer.new(:int)
    Native.raise!(Native.antech_needs_rehash(encoded_hash, out))
    out.read_int != 0
  end

  def needs_rehash_with_policy(encoded_hash, policy)
    out = FFI::MemoryPointer.new(:int)
    Native.raise!(Native.antech_needs_rehash_with_policy(encoded_hash, policy.to_native, out))
    out.read_int != 0
  end
end
