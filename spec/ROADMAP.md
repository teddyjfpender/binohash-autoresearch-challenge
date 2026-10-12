# Roadmap

The repository is built to hold several challenges. Each one is a directory under
`challenges/` with the same parts, and the shared tooling in `tools/bac` and the workflows read
them through `challenges.json`.

## What a challenge provides

| Part | File |
| --- | --- |
| Contract: tracks, editable and trusted paths, validation, acceptance | `benchmark.json` |
| Task for an optimisation agent | `TASK.md` |
| Trusted evaluator and editable builders | challenge-specific |
| Security model and cost model | `spec/` |
| Architecture registry | `architectures.json` |
| Published points to compare against | `targets.json` |
| Starting board and ledger of validated instances | `starting-board.json`, `results.tsv` |

Adding a challenge means adding that directory and one entry in `challenges.json`. The path
policy, the submission manifest, the ledger, the site feed and the judge workflow are shared.

## Order of work for Binohash

1. **Record the starting board** under the ledger key and move the tracks' baselines from
   pending to recorded ([OPERATIONS.md](OPERATIONS.md)). Done for the first board, and again
   for the six instances kept under BH-SEC-2.
2. **First submission judged end to end** on hosted runners.
3. **Independent review of BH-SEC-2**, in particular of the puzzle accounting (8 bits per byte,
   where the paper states 8 bits plus 2), of the two attacks it prices rounds by and of the
   pinning cap. Searches have corrected the model twice: once before the board was recorded,
   and again when an agent search found that a partial search helps the attacker and that
   pinning was credited at any puzzle size. The model does not price what an attacker gains
   at the cap, and it leaves hash-type byte freedom out; a two-sided estimate of about 4 bits
   per round beyond the first has not been reconciled with the paper's figure of under one
   bit.
4. **A production spend.** One transaction ground at full difficulty for the baseline of the
   `standard` track and accepted by Bitcoin Core, on regtest with a pinned node. This closes the
   gap between the test twin and the production script for one instance, and with it the
   reproduction asked for by open problem OP-011 of the bitcoin-scripts knowledge base.
5. **Move from `staging` to `live`** once the gates in `data/site/activation.json` are met.

## Contract epochs under consideration

Each needs evaluator support, a security argument and tests that break it on purpose
([VALIDATION.md](VALIDATION.md#changing-the-contract)). None is open.

| Mechanism | What it would change | What is missing |
| --- | --- | --- |
| Polyglot digest (Binohash appendix D) | Pool signatures that are themselves commitments: about 3.7 kB and two operations per selection less | A test twin for elements that cost 2^46 hashes each to make, and setup work in the work model |
| Sub-byte puzzle difficulty | Puzzle work in steps finer than 8 bits, so a level can be set between the ones whole bytes allow | A puzzle kind the evaluator can count |
| Pools shared between rounds | Half the signature bytes | An analysis of correlated rounds in the security model |
| Hash-type freedom in the model | The on-chain half of a collision is cheaper (Binohash 7.2) | A scored treatment instead of a stated exclusion |
| Conditional execution | Scripts with branches | An audit that covers every branch |
| Hash-to-signature puzzles (QSB) | No dependence on the shortest known nonce | A different challenge: different work, different model |

## Candidate challenges

Constructions of the same kind that the same machinery could host. These are candidates, not
commitments: one opens only when it has a pinned acceptance standard, a trusted evaluator and a
starting board.

| Challenge | Construction |
| --- | --- |
| Quantum-safe Binohash | The QSB variant: hash-to-signature puzzles, cost against second-preimage resistance. |
| One-time signatures in Script | Lamport, HORS and Winternitz verification under the legacy and tapscript limits. |
| Hash functions in Script | SHA-256 and BLAKE3 compression without `OP_CAT`, scored by bytes and stack. |
