# Candidate E1 — Family E1: Hidden Continuation

**Status: EXPERIMENTAL / NOT PRODUCTION SAFE**

## Overview
Sequence where expensive continuation cannot be skipped based on public information.

- **Hypothesis**: Forcing attackers to execute sequential state updates without early rejection prevents cheap wrong-candidate filtering.
- **Defender RAM Target**: 4 MiB to 32 MiB on 1-core / 1-GB server.
