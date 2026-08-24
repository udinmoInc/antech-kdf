# Threat Model

## Primary Target
Offline password cracking attacks where an attacker gains access to derived password hash strings from a compromised database.

## Attacker Capabilities Model
- Multi-core CPU clusters
- High-throughput GPU arrays (NVIDIA / AMD)
- Custom FPGA acceleration units
- Custom ASIC hardware implementations

## Defensive Focus
Maximizing cost/energy per guess by saturating memory bandwidth and enforcing strict sequential instruction dependencies while minimizing peak server memory footprints.
