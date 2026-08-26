# 01 — Problem

Memory-hard password KDFs raise the cost of offline guessing by forcing each guess to touch a large working set. Argon2id is commonly deployed around 64 MiB per verify. That is fine on idle hosts and painful on small VPS boxes or tightly capped containers when many verifies run at once.

Cutting Argon2’s memory parameter to fit the box also cuts attacker cost. The question this project started with: can a different construction keep useful offline cost at about **16 MiB** of defender RAM?

Production today is the **combined-frontier** compute-memory engine in `antech-kdf-core` (construction version 4, `$antech$v2$`). Early candidate forks and superseded campaigns are archived under `research/archive/` and are not the numbers to cite for the shipping library.
