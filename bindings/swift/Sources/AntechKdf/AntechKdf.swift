import CAntechKdf
import Foundation

public enum AntechError: Error {
  case invalidInput
  case invalidHash
  case invalidConfig
  case internalError(Int32)
}

public struct Config {
  public var memoryKib: UInt32
  public var saltLength: UInt32
  public var blockSize: UInt32
  public var fanIn: UInt32
  public var graph: UInt32
  public var outputLength: UInt32

  public static func `default`() throws -> Config {
    var c = AntechConfig()
    try raise(antech_config_default(&c))
    return Config(
      memoryKib: c.memory_kib,
      saltLength: c.salt_length,
      blockSize: c.block_size,
      fanIn: c.fan_in,
      graph: c.graph,
      outputLength: c.output_length
    )
  }

  fileprivate func withC<R>(_ body: (inout AntechConfig) throws -> R) rethrows -> R {
    var c = AntechConfig(
      memory_kib: memoryKib,
      salt_length: saltLength,
      block_size: blockSize,
      fan_in: fanIn,
      graph: graph,
      output_length: outputLength
    )
    return try body(&c)
  }
}

public struct RehashPolicy {
  public var minimumMemoryKib: UInt32
  public var preferredMemoryKib: UInt32
  public var preferredFanIn: UInt32
  public var preferredOutputLength: UInt32
  public var preferredSecretRequired: Bool
  public var preferredAssociatedData: Bool

  public static func `default`() throws -> RehashPolicy {
    var p = AntechRehashPolicy()
    try raise(antech_rehash_policy_default(&p))
    return RehashPolicy(
      minimumMemoryKib: p.minimum_memory_kib,
      preferredMemoryKib: p.preferred_memory_kib,
      preferredFanIn: p.preferred_fan_in,
      preferredOutputLength: p.preferred_output_length,
      preferredSecretRequired: p.preferred_secret_required != 0,
      preferredAssociatedData: p.preferred_associated_data != 0
    )
  }
}

private func raise(_ st: AntechStatus) throws {
  switch st {
  case ANTECH_OK: return
  case ANTECH_INVALID_INPUT: throw AntechError.invalidInput
  case ANTECH_INVALID_HASH: throw AntechError.invalidHash
  case ANTECH_INVALID_CONFIG: throw AntechError.invalidConfig
  default: throw AntechError.internalError(st.rawValue)
  }
}

private func takeString(_ ptr: UnsafeMutablePointer<CChar>?) throws -> String {
  guard let ptr else { throw AntechError.internalError(-3) }
  defer { antech_free(ptr) }
  return String(cString: ptr)
}

public enum AntechKdf {
  public static func version() -> String {
    String(cString: antech_version())
  }

  public static func hash(_ password: String) throws -> String {
    try hash(Data(password.utf8))
  }

  public static func hash(_ password: Data) throws -> String {
    var out: UnsafeMutablePointer<CChar>?
    let st: AntechStatus = password.withUnsafeBytes { raw in
      let base = raw.bindMemory(to: UInt8.self).baseAddress
      return antech_hash_bytes(base, password.count, &out)
    }
    try raise(st)
    return try takeString(out)
  }

  public static func hashWithConfig(_ password: Data, config: Config) throws -> String {
    var out: UnsafeMutablePointer<CChar>?
    let st: AntechStatus = try config.withC { cfg in
      password.withUnsafeBytes { raw in
        let base = raw.bindMemory(to: UInt8.self).baseAddress
        return antech_hash_with_config_bytes(base, password.count, &cfg, &out)
      }
    }
    try raise(st)
    return try takeString(out)
  }

  public static func hashWithConfigAndSalt(
    _ password: Data,
    salt: Data,
    config: Config
  ) throws -> String {
    var out: UnsafeMutablePointer<CChar>?
    let st: AntechStatus = try config.withC { cfg in
      password.withUnsafeBytes { pwRaw in
        salt.withUnsafeBytes { saltRaw in
          let pw = pwRaw.bindMemory(to: UInt8.self).baseAddress
          let s = saltRaw.bindMemory(to: UInt8.self).baseAddress
          return antech_hash_with_config_and_salt(
            pw, password.count, s, salt.count, &cfg, &out
          )
        }
      }
    }
    try raise(st)
    return try takeString(out)
  }

  public static func verify(_ password: String, encodedHash: String) throws -> Bool {
    try verify(Data(password.utf8), encodedHash: encodedHash)
  }

  public static func verify(_ password: Data, encodedHash: String) throws -> Bool {
    let st: AntechStatus = password.withUnsafeBytes { raw in
      let base = raw.bindMemory(to: UInt8.self).baseAddress
      return encodedHash.withCString { cHash in
        antech_verify_bytes(base, password.count, cHash)
      }
    }
    return try asVerified(st)
  }

  public static func needsRehash(_ encodedHash: String) throws -> Bool {
    var out: Int32 = 0
    try encodedHash.withCString { c in
      try raise(antech_needs_rehash(c, &out))
    }
    return out != 0
  }

  public static func needsRehashWithPolicy(_ encodedHash: String, policy: RehashPolicy) throws -> Bool {
    var out: Int32 = 0
    var p = AntechRehashPolicy(
      minimum_memory_kib: policy.minimumMemoryKib,
      preferred_memory_kib: policy.preferredMemoryKib,
      preferred_fan_in: policy.preferredFanIn,
      preferred_output_length: policy.preferredOutputLength,
      preferred_secret_required: policy.preferredSecretRequired ? 1 : 0,
      preferred_associated_data: policy.preferredAssociatedData ? 1 : 0
    )
    try encodedHash.withCString { c in
      try raise(antech_needs_rehash_with_policy(c, &p, &out))
    }
    return out != 0
  }

  // nil = absent; empty Data = present-but-empty. See antech_kdf.h.
  public static func hashWithInputs(
    _ password: Data,
    config: Config,
    secret: Data? = nil,
    associatedData: Data? = nil
  ) throws -> String {
    var out: UnsafeMutablePointer<CChar>?
    let st: AntechStatus = try config.withC { cfg in
      try withOptional(secret) { secPtr, secLen in
        try withOptional(associatedData) { adPtr, adLen in
          password.withUnsafeBytes { raw in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            return antech_hash_with_inputs_bytes(
              base, password.count, &cfg, secPtr, secLen, adPtr, adLen, &out
            )
          }
        }
      }
    }
    try raise(st)
    return try takeString(out)
  }

  public static func hashWithInputsAndSalt(
    _ password: Data,
    salt: Data,
    config: Config,
    secret: Data? = nil,
    associatedData: Data? = nil
  ) throws -> String {
    var out: UnsafeMutablePointer<CChar>?
    let st: AntechStatus = try config.withC { cfg in
      try withOptional(secret) { secPtr, secLen in
        try withOptional(associatedData) { adPtr, adLen in
          password.withUnsafeBytes { pwRaw in
            salt.withUnsafeBytes { saltRaw in
              let pw = pwRaw.bindMemory(to: UInt8.self).baseAddress
              let s = saltRaw.bindMemory(to: UInt8.self).baseAddress
              return antech_hash_with_inputs_and_salt(
                pw, password.count, s, salt.count, &cfg,
                secPtr, secLen, adPtr, adLen, &out
              )
            }
          }
        }
      }
    }
    try raise(st)
    return try takeString(out)
  }

  public static func verifyWithInputs(
    _ password: Data,
    encodedHash: String,
    secret: Data? = nil,
    associatedData: Data? = nil
  ) throws -> Bool {
    let st: AntechStatus = try withOptional(secret) { secPtr, secLen in
      try withOptional(associatedData) { adPtr, adLen in
        password.withUnsafeBytes { raw in
          let base = raw.bindMemory(to: UInt8.self).baseAddress
          return encodedHash.withCString { cHash in
            antech_verify_with_inputs_bytes(
              base, password.count, cHash, secPtr, secLen, adPtr, adLen
            )
          }
        }
      }
    }
    return try asVerified(st)
  }
}

private func asVerified(_ st: AntechStatus) throws -> Bool {
  if st == ANTECH_OK { return true }
  if st == ANTECH_VERIFICATION_FAILED { return false }
  try raise(st)
  return false
}

private func withOptional<R>(
  _ data: Data?,
  _ body: (UnsafePointer<UInt8>?, Int) throws -> R
) rethrows -> R {
  guard let data else {
    return try body(nil, 0)
  }
  if data.isEmpty {
    var scratch: UInt8 = 0
    return try withUnsafePointer(to: &scratch) { ptr in
      try body(ptr, 0)
    }
  }
  return try data.withUnsafeBytes { raw in
    let base = raw.bindMemory(to: UInt8.self).baseAddress
    return try body(base, data.count)
  }
}
