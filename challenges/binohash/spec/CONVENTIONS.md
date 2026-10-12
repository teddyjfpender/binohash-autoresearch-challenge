# Conventions

How this challenge counts and names things, and how its figures relate to those of the paper
and of other catalogues of Bitcoin Script constructions.

## Boundaries

Every figure states what it includes.

| Figure | Boundary |
| --- | --- |
| `locking_bytes` | The complete locking script: the scriptPubKey of a bare output, without its length prefix and value. |
| `unlocking_bytes` | The complete unlocking script (scriptSig) of an honest spend at production signature sizes, without its length prefix. The largest it can be: each index at its widest push. |
| `bytes` | The sum of the two. Complete-input boundary: what the Binohash output and its spend add to the chain, except the output's value and length prefix and the input's outpoint, length prefix and sequence. The rest of the spending transaction is not counted. |
| `opcodes` | Executed, as the interpreter counts them for the limit of 201: every opcode above `OP_16` in the locking script plus the number of public keys of each executed `OP_CHECKMULTISIG`. Scripts are straight-line, so executed and static counts coincide except for the multisig keys. The unlocking script is push-only and adds none. |
| `stack_peak` | Combined main and alt stack, counted after every operation of both scripts, hints and constants included. |
| `work_bits` | SHA-256 compressions, expected, one spend, reference grinder ([WORK-MODEL.md](WORK-MODEL.md)). |
| `security_bits` | Sighash evaluations, best known collision attack ([SECURITY-MODEL.md](SECURITY-MODEL.md)). |

Work and security are in different units on purpose. Security follows the paper's unit so that
levels can be read against it; a compression count for the attacker would be higher by a
layout-dependent factor, which would let a layout change move the fixed quantity.

## Execution context

- **Script context:** legacy, bare output. Not P2SH (the script exceeds 520 bytes), not SegWit,
  not Taproot: FindAndDelete and the `SIGHASH_SINGLE` bug exist only in legacy signature hashing.
- **Rules applied:** consensus for a pre-Taproot legacy input: strict DER (BIP 66), NULLDUMMY
  (BIP 147), the 10,000-byte, 201-operation, 520-byte and 1,000-item limits. Relay policy is
  not applied and not claimed: these spends violate `CONST_SCRIPTCODE`, clean-stack and
  standard-script rules and need a miner that accepts non-standard transactions.
- **Interpreters:** the reference engine in `evaluator/bh/interp.py`, and Bitcoin Core's
  consensus library 26.0 through `tools/core` where a row's `engine` says `+core`.
- **Unsupported:** `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY` and conditionals are
  refused by the evaluator, not modelled.

## Evidence

A ledger row is evidence of a stated kind and no more. In the vocabulary of the
[bitcoin-scripts knowledge base](https://github.com/solving-bitcoin/bitcoin-scripts)
(`knowledge/evidence.md`):

| Claim | Level |
| --- | --- |
| Byte, opcode and stack counts | Locally reproduced: deterministic from the instance. |
| Honest spends of the test twin are valid; altered ones are refused | Differentially validated against Bitcoin Core's consensus library, for the spends replayed, when the row's engine includes `core`. Otherwise locally reproduced. |
| The production script behaves as the test twin | Inspected: by the twin rule, not by execution. |
| Puzzle work | Locally reproduced arithmetic, given assumption A1. |
| The security level | A claim under BH-SEC-2's assumptions, with an audit as supporting evidence. Not a proof. |
| Deployment class | Consensus-validated for the test twin's spends replayed through Core. Not policy-validated; no funded transaction, regtest or otherwise, is part of the judge. |

That knowledge base lists reproducing Binohash as open problem OP-011, complete when
"extraction correctness, collision/work parameters, full transaction costs, mutation
boundaries, and malformed/grinding failure cases are reproduced from deterministic fixtures"
against a pinned Core. The evaluator covers extraction, parameters, input-level costs and
failure cases with deterministic fixtures and a pinned consensus library. It does not run a
regtest node or fund a transaction, and it grinds the test twin, not the production puzzles.

## Names

- **Instance:** one locking script with its test twin and witness description. The unit a row
  records, named by `instance_sha256`.
- **Pool, element:** a round's `n` script-embedded signatures; one of them with its commitment.
- **Selection:** `t` elements of a pool. **Digest:** one selection per round.
- **Slot:** the position of an element in a selection as the witness lists it.
- **Pinning puzzle, round puzzle:** a signature-size puzzle on a transaction-bound signature;
  the one verified inside a round's multisig.
- **Lane:** one judge-chosen transaction and everything the judge does with it.
- **Specimen:** an instance whose secrets are public. Every judged instance is one.

## Numbers

Counts are integers. `work_bits` and `security_bits` are computed in 50-digit decimal
arithmetic and written to `score.json` with six places; the ledger keeps three. The score is
computed from the ledger's own cells in decimal arithmetic, so it is the same on every machine.
