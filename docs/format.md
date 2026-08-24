# Password Hash Format Specification

## String Syntax

```
$antech$<version>$m=<memory_kib>,t=<time_cost>,p=<parallelism>,bw=<bandwidth_target>$<salt_b64>$<digest_b64>
```

## Fields

1. `prefix`: `$antech$`
2. `version`: `v1`
3. `parameters`: Key-value pairs:
   - `m`: Memory allocation in KiB.
   - `t`: Time cost / iteration count.
   - `p`: Parallelism / lanes.
   - `bw`: Target memory bandwidth (MB/s).
4. `salt`: Standard Base64 (no padding) encoded salt bytes.
5. `digest`: Standard Base64 (no padding) encoded derived key bytes.
