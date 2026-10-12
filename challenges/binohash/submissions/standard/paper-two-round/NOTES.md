# Binohash paper, two rounds of 120-choose-8, 5-byte puzzles

The baseline of the `standard` track: the construction of the Binohash paper with its published
parameters, built by `builders/paper.py`.

## Goal and starting point

Reproduce the paper's "Maximum" configuration (section 6.2) as an instance the evaluator can
judge, so that everything on the board is measured against the published construction under one
set of counting rules. It builds on no earlier submission.

## Mechanism

- **Pinning** is Appendix A: a hardcoded nine-byte `SIGHASH_SINGLE` signature checked against its
  recovered key, then four `OP_SIZE <55> OP_EQUALVERIFY <key> OP_CHECKSIGVERIFY` puzzles. The
  keys are `d_i * G` with `d_i = -2^(256 - 42 + i) / r_min`, so the four puzzles accept disjoint
  sets of sighashes and need four different sighash modes.
- **Each round** is the Appendix B listing: 120 HASH160 commitments and 120 nine-byte signatures
  are pushed, and eight iterations of `ROLL MIN DUP ADD ROLL ROLL HASH160 EQUALVERIFY ROLL`
  select eight signatures and open their commitments. The puzzle signature is rolled up, checked
  to be 55 bytes, and verified with the selection by a 9-of-9 `OP_CHECKMULTISIG` under eight
  witness keys and the puzzle key `(1 / r_min) * G`.
- The witness index of slot `i` is the rank of the chosen element among those still on the stack,
  plus `i + 1`, so that the same number addresses the signature directly and the commitment
  after one `OP_ADD`. The keys are rolled deepest first, which keeps their depth constant.

## Architecture

`rolled-subset`: it is the registry entry's reference construction.

## Experiments

Counted by the evaluator on public lanes (`python3 challenge.py run`):

| | This evaluator | Paper |
| --- | ---: | ---: |
| Opcodes | 199 | about 199 |
| Locking script | 8,101 bytes | 8,028 bytes |
| Unlocking script | 1,248 bytes | not stated |
| Puzzle work per signature | 40.006 bits | 42 bits |
| Security (BH-SEC-2) | 80.011 bits | about 84 bits |
| Honest work | 2^46.740 compressions | 2^44.6 sighash evaluations |

Differences from the paper, all explained in `spec/SECURITY-MODEL.md` and `spec/WORK-MODEL.md`:

- A 55-byte signature costs 8 x 5 = 40 bits, not 42. The interpreter accepts both nonce signs
  and values of `s` that wrap around the group order; a spend ground through each of the four
  cases was replayed through Bitcoin Core's consensus library and accepted.
- With 2^39.61 selections against a 2^40.006 puzzle, a round has a solution for a given
  transaction with probability 0.53, and both rounds do with probability 0.28. The spender
  tries 3.5 transactions on average, solving one pinning puzzle again for each. The attacker
  profits from the same thing: a transaction whose first round has no solution is abandoned,
  which is 0.2 bits of the gap to the paper's figure.
- The level is the pinning cap, not what the rounds are worth. The rounds alone come to 81.521
  bits. Four pinning puzzles force four sighash modes only while one signature mode cannot
  serve two of them, which costs the work of two puzzles, 80.011 bits. BH-SEC-2
  credits no level above that, so this configuration counts as 80.011.
- A round-0 attempt hashes 71 SHA-256 blocks and a round-1 attempt 9, because round 1's pool sits
  later in the script and more of the preimage is a fixed prefix.

What did not work: rolling the witness keys shallowest first. The depth then grows by one per
key; rolling the deepest remaining key keeps one constant, as the paper's listing does.

## Result and next steps

The numbers above. Obvious directions for a first improvement: the 71-block round-0 attempts
dominate the work and are a property of the layout, not of the construction; the selection loop
is nine counted operations per element; and the pool size could be chosen so that a round more
often has a solution, at a cost in bytes. The floor of this track is 80.0 bits and the rounds
have 1.5 bits to spare above it, so that trade is open as long as the rounds stay worth at
least the floor; the level itself stays at the cap.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. The
construction is Robin Linus's (Binohash, 2026).
