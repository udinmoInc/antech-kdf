# Antech KDF — Hash Format

Canonical stored-hash encoding is **version v2**:

```text
$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>$<salt_hex>$<digest_hex>
```

| Field | Meaning |
|---|---|
| `m` | Memory in KiB |
| `s` | Salt length in bytes |
| `b` | Block size in bytes |
| `f` | Fan-in |
| `g` | Graph kind tag (`1` reduced-critical-path, `2` cache-locality, `3` combined-frontier) |
| `l` | Output digest length in bytes |

Salt and digest are hex-encoded.

## Verification

`verify()` parses the string, reconstructs `AntechConfig`, derives with the canonical engine, and compares digests in constant time. Callers do not supply salt or parameters separately.

## Legacy encodings

Version `v1` (and any other unrecognized version) is **rejected**. Legacy strings are not reinterpreted.
