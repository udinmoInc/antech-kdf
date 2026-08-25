# 01 — Problem

Memory-hard password KDFs raise the cost of offline guessing by forcing each guess to touch a large working set. Argon2id is commonly deployed around 64 MiB per verify. That is fine on idle hosts and painful on small VPS boxes or tightly capped containers when many verifies run at once.

Cutting Argon2id's memory parameter to fit the box also cuts attacker cost. The question this project started with: can a different construction keep useful offline cost at about **16 MiB** of defender RAM?

Later chapters cover baselines, designs that were tried, measured CPU/GPU numbers, and limits. Production code today is the combined-frontier compute-memory engine, not the early K1/K2 research variants.
