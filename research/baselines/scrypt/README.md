# scrypt Baseline Research

## Overview
scrypt (RFC 7914) is a sequential memory-hard password KDF designed to make large-scale hardware attacks costly by requiring large amounts of memory.

## Baseline Metrics (Target Profile: N=16384, r=8, p=1)
- **Peak Memory**: 16 MiB.
- **Server Latency**: ~20-40 ms.

## Evaluation Goals
Compare scrypt's sequential memory access patterns against Antech bandwidth-hard churn models.
