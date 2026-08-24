# Antech KDF — Hash String Encoding Specification

Antech KDF generates self-describing, standard string encodings. All algorithmic parameters, version identifier, salt, and output digest are embedded directly within the string.

---

## 🎨 Encoded String Format Anatomy

```text
$antech$v1$m=16384,t=650000,p=1$42424242424242424242424242424242$a1f9b3c2d4e5f6...
  │     │   │                    │                                │
  │     │   │                    │                                └── Output Digest (Hex Encoded)
  │     │   │                    └────────────────────────────────── Salt Bytes (16 bytes Hex Encoded)
  │     │   └────────────────────────────────────────────────────── Parameters (m=Memory, t=Depth, p=Passes)
  │     └────────────────────────────────────────────────────────── Algorithm Version Identifier (v1)
  └──────────────────────────────────────────────────────────────── Header Identifier ($antech$)
```

---

## 🧩 Field Breakdown

```mermaid
graph LR
    H["$antech$"] --> V["v1"]
    V --> P["m=16384,t=650000,p=1"]
    P --> S["Hex Salt (32 chars)"]
    S --> D["Hex Digest (64 chars)"]
```

| Token Field | Description | Example Value |
| :--- | :--- | :--- |
| `Header` | Fixed algorithm prefix identifier | `$antech$` |
| `Version` | Major format version tag | `v1` |
| `m` | Working memory footprint in KiB | `16384` (16 MiB) |
| `t` | Sequential dependency step depth | `650000` steps |
| `p` | Execution pass count | `1` pass |
| `Salt` | Cryptographically secure salt (Hex) | `42424242424242424242424242424242` |
| `Digest` | Derived 256-bit output hash (Hex) | `a1f9b3c2d4e5f6...` |

---

## 💻 Rust Format Parsing Code Snippet

```rust
use antech_kdf_format::{encode_hash, parse_hash, HashFormat};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let salt = [0x42u8; 16];
    let digest = [0xa1u8; 32];
    let memory_kib = 16384;
    let dependency_depth = 650000;
    let passes = 1;

    // 1. Encode into self-describing hash string
    let formatted = encode_hash(memory_kib, dependency_depth, passes, &salt, &digest)?;
    println!("Formatted String: {}", formatted);

    // 2. Parse hash string back into structured components
    let parsed = parse_hash(&formatted)?;
    assert_eq!(parsed.memory_kib, 16384);
    assert_eq!(parsed.dependency_depth, 650000);
    assert_eq!(parsed.salt, salt);
    assert_eq!(parsed.digest, digest);

    Ok(())
}
```
