# Candidate-004 Algorithm Specification

**Status: EXPERIMENTAL RESEARCH SPECIFICATION (v1.0)**

## 1. Parameters
- `memory_kib` ($M$): Memory allocation size in KiB (default: 16384 = 16 MiB).
- `dependency_depth` ($D$): Number of sequential ARX churn rounds (default: 120).
- `passes` ($p$): Number of passes over memory (default: 1).
- `block_size`: 32 bytes (4 $\times$ u64 words).

## 2. Execution Pseudocode
```python
def derive_candidate_004(password, salt, memory_kib=16384, depth=120):
    size = memory_kib * 1024
    num_blocks = size // 32
    
    # 1. Seed Initialization
    seed = SHA256("antech-v1-domain-separator-2026" || password || salt || memory_kib || depth)
    
    # 2. Buffer Filling
    buffer = bytearray(size)
    for i in range(size):
        buffer[i] = seed[i % 32] ^ (i & 0xFF)
        
    # 3. State Setup
    state = [u64_from_le(seed[i*8:(i+1)*8]) for i in range(4)]
    
    # 4. Sequential Memory Churn Loop
    for step in range(depth):
        block_idx = state[0] % num_blocks
        offset = block_idx * 32
        block = load_u64_x4(buffer[offset:offset+32])
        
        state[0] = (state[0] + block[0]).rotate_left(19) ^ step
        state[1] = (state[1] + block[1]).rotate_left(29) ^ state[0]
        state[2] = (state[2] + block[2]).rotate_left(13) ^ state[1]
        state[3] = (state[3] + block[3]).rotate_left(37) ^ state[2]
        
        for i in range(4):
            buffer[offset + i*8 : offset + (i+1)*8] = u64_to_le(block[i] ^ state[i])
            
    # 5. Final Digest
    return SHA256("antech-v1-finalization" || u64_to_le(state))
```

## 3. Encoded Hash Format
`$antech$v1$m=16384,t=120,p=1$<salt_hex>$<digest_hex>`
