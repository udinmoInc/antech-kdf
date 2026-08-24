# Security & Implementation Guarantees

## Memory Protection
- Secret key buffers zeroized on drop (`zeroize::Zeroizing`).
- Constant-time comparison for derived digest verification (`subtle::ConstantTimeEq`).

## Side-Channel Considerations
- All password comparison checks are performed in constant time regardless of match failure index.
- Verification returns `Ok(false)` on password mismatch to prevent leaking error status types.

## Status Warning
Antech KDF is an experimental research project. Do NOT deploy to production systems.
