# Reviewer Checklist — Antech KDF

- [ ] Independent implementation matches [`test-vectors.json`](./test-vectors.json)
- [ ] Graph construction (CombinedFrontier) independently verified
- [ ] State transition (`MixPair` / `MixViews`) independently verified
- [ ] Parent selection analyzed
- [ ] DAG reduction attempted
- [ ] TMTO analyzed
- [ ] Multi-target analyzed
- [ ] Parallelization analyzed
- [ ] GPU implementation considered
- [ ] ASIC/FPGA considered
- [ ] Side channels considered
- [ ] Parameter manipulation considered
- [ ] Password/salt binding analyzed
- [ ] No early rejection shortcut
- [ ] No practical reduced-work attack found *(or attack documented with reproduction)*

Notes / findings:  
_…_
