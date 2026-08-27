# Thin Crystal wrapper (bindings/c/antech_kdf.h). Link -lantech_kdf.

@[Link("antech_kdf")]
lib LibAntech
  struct Config
    memory_kib : UInt32
    salt_length : UInt32
    block_size : UInt32
    fan_in : UInt32
    graph : UInt32
    output_length : UInt32
  end

  fun antech_version : UInt8*
  fun antech_free(ptr : UInt8*)
  fun antech_config_default(out : Config*) : Int32
  fun antech_hash_bytes(password : UInt8*, password_len : LibC::SizeT, out_hash : UInt8**) : Int32
  fun antech_hash_with_config_bytes(password : UInt8*, password_len : LibC::SizeT, config : Config*, out_hash : UInt8**) : Int32
  fun antech_verify_bytes(password : UInt8*, password_len : LibC::SizeT, encoded_hash : UInt8*) : Int32
  fun antech_needs_rehash(encoded_hash : UInt8*, out_needs_rehash : Int32*) : Int32
end

module Antech
  VERSION = "0.1.0"
  GRAPH_COMBINED_FRONTIER = 3_u32

  class Error < Exception
  end

  class Config
    property memory_kib : UInt32
    property salt_length : UInt32
    property block_size : UInt32
    property fan_in : UInt32
    property graph : UInt32
    property output_length : UInt32

    def initialize(@memory_kib = 16384_u32, @salt_length = 16_u32, @block_size = 32_u32,
                   @fan_in = 2_u32, @graph = 3_u32, @output_length = 32_u32)
    end

    def self.default : Config
      c = LibAntech::Config.new
      Antech.raise!(LibAntech.antech_config_default(pointerof(c)))
      new(c.memory_kib, c.salt_length, c.block_size, c.fan_in, c.graph, c.output_length)
    end

    def to_native : LibAntech::Config
      c = LibAntech::Config.new
      c.memory_kib = @memory_kib
      c.salt_length = @salt_length
      c.block_size = @block_size
      c.fan_in = @fan_in
      c.graph = @graph
      c.output_length = @output_length
      c
    end
  end

  def self.raise!(st : Int32) : Nil
    return if st == 0
    msg = case st
          when -1 then "invalid input"
          when -2 then "invalid hash"
          when -4 then "invalid config"
          else         "internal error (#{st})"
          end
    raise Error.new(msg)
  end

  def self.take(ptr : UInt8*) : String
    raise Error.new("null string") if ptr.null?
    s = String.new(ptr)
    LibAntech.antech_free(ptr)
    s
  end

  def self.version : String
    p = LibAntech.antech_version
    p.null? ? VERSION : String.new(p)
  end

  def self.hash(password : String) : String
    out = Pointer(UInt8).null
    raise!(LibAntech.antech_hash_bytes(password.to_unsafe, LibC::SizeT.new(password.bytesize), pointerof(out)))
    take(out)
  end

  def self.hash_with_config(password : String, config : Config) : String
    c = config.to_native
    out = Pointer(UInt8).null
    raise!(LibAntech.antech_hash_with_config_bytes(
      password.to_unsafe, LibC::SizeT.new(password.bytesize), pointerof(c), pointerof(out)))
    take(out)
  end

  def self.verify(password : String, encoded_hash : String) : Bool
    st = LibAntech.antech_verify_bytes(
      password.to_unsafe, LibC::SizeT.new(password.bytesize), encoded_hash.to_unsafe)
    return true if st == 0
    return false if st == 1
    raise!(st)
  end

  def self.needs_rehash(encoded_hash : String) : Bool
    needs = 0
    raise!(LibAntech.antech_needs_rehash(encoded_hash.to_unsafe, pointerof(needs)))
    needs != 0
  end
end
