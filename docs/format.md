# Hash format

Current encoding is version `v2`:

```text
$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>$<salt_hex>$<digest_hex>
```

| Field | Meaning |
|---|---|
| `m` | Memory (KiB) |
| `s` | Salt length (bytes) |
| `b` | Block size (bytes) |
| `f` | Fan-in |
| `g` | Graph tag: `1` reduced-critical-path, `2` cache-locality, `3` combined-frontier |
| `l` | Digest length (bytes) |

Salt and digest are lowercase hex. Declared lengths must match the decoded byte lengths or parsing fails.

`verify` parses the string, rebuilds `AntechConfig`, runs the engine, and compares digests with `subtle::ConstantTimeEq`. Callers do not pass salt or parameters separately.

Version `v1` and any unrecognized version are rejected. Old research strings are not reinterpreted.
