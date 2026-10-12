# Binohash paper, two rounds of 120-choose-8, 6-byte pinning

The baseline of the `high` track: the paper's "Higher W1" configuration (section 6.2), built by
`builders/paper.py`.

## Goal and starting point

The same construction as `standard/paper-two-round` with pinning signatures of 54 bytes instead
of 55. The paper presents this as the way to raise collision resistance without spending
opcodes: the size constant changes and nothing else does.

## Mechanism

Identical to `standard/paper-two-round` except `BINO_PIN_BYTES=6`: the four pinning puzzles
check `OP_SIZE <54>`, and their keys follow Appendix A with W1 = 50, so their targets stay
disjoint. The rounds are unchanged: two rounds of 120-choose-8 under 5-byte puzzles.

## Architecture

`rolled-subset`, as the parent construction.

## Experiments

Counted by the evaluator on public lanes (`python3 challenge.py run`):

| | This evaluator | Paper |
| --- | ---: | ---: |
| Opcodes | 199 | about 199 |
| Bytes (locking + unlocking) | 8,101 + 1,244 | 8,028 locking |
| Pinning work per signature | 48.006 bits | 50 bits |
| Security (BH-SEC-2) | 88.411 bits | about 92 bits |
| Honest work | 2^52.246 compressions | 2^52.6 sighash evaluations |

The gap between 88.4 and the paper's 92 has two parts. Two bits are the puzzle accounting (a
signature n bytes short costs 8n bits, not 8n + 2). The rest is the digest: the paper's row uses
W1 + W2, while its own section 5.3 formula gives the pinning work plus the 39.6 bits of one
round's selections. The pinning cap of BH-SEC-2 is the work of two pinning puzzles, 96.011 bits here, and does not
bind.

Honest work is almost entirely pinning here: three puzzles of 2^48 attempts once, and the
`SIGHASH_ALL` puzzle again for each of the 3.5 transactions tried on average, because both
rounds have a solution for only 28% of them. That last factor is where this track differs from
`standard`: every failed round costs a 2^48 puzzle, so how often a round fails matters far more.

Nothing was tried beyond the published parameters; this is the reference point.

## Result and next steps

The numbers above. The 48 bits have to sit in the pinning puzzles on this track. An instance
that put them in one round and kept 5-byte pinning (`high/late-round48`, recorded on the first
board under the old model BH-SEC-1) was removed: BH-SEC-2 caps a level at the work of two
pinning puzzles, 80.011 bits with 5-byte pinning, which is below this track's floor of 88.4.
What is left to move is how often a round fails, since each failure costs a 2^48 puzzle, and
the floor limits that: with pinning dominant, more selections lower the level.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. The
construction is Robin Linus's (Binohash, 2026).
