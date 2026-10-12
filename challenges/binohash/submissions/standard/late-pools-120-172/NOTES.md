# Late pools, 120-choose-8 and 172-choose-8

The lowest score found on the `standard` track in the first search: 1.67 times below the
baseline, bought with 1.6 kB more script.

## Goal and starting point

`standard/late-pools`. With two pools of 120 a round has a solution for a given transaction
53% of the time, both rounds 28%, so 3.5 transactions are tried per spend. Larger pools fail
less often, but under BH-SEC-1 more selections lower the security level, and the baseline sits
0.02 bits above the floor.

## Mechanism

The two rounds do not have to be equal. Keep round 0 at 120-choose-8 (2^39.6 selections, a
solution 53% of the time) and give round 1 172 elements (2^43.9 selections, 15 solutions on
average, a solution essentially always).

Under the exhaustive-birthday attack the large round costs the attacker 2^43.9 evaluations per
transaction that reaches it, against 2^39.6 before, while the digest space it adds is only
partly usable: `W - E/2` falls by 2.1 bits and the cost per transaction rises by 2.1. The level
stays at 81.52. The stored-digest attack, which does not pay for large pools, comes down to
meet it at the same figure, and that is what stops the pool at 172. For the honest spender one
round almost never fails, so 1.9 transactions are tried instead of 3.5.

The round with 120 elements is round 0, last in the script, so that the pool every attempt of
the other round has to rehash is the small one.

## Soundness

The script is `late-pools` with a different pool size in one round; the argument there applies
unchanged. The level is the evaluator's. This instance sits exactly where the two attacks of
BH-SEC-1 meet (81.53 for the exhaustive birthday, 81.52 for stored digests), so it is the kind
of instance a third attack family would hurt first; see the model's own caveat.

## Experiments

An exact count (no lanes) over pool sizes 70 to 230 and 6 to 10 selections per round, both
orders, 5-byte puzzles, 4,000 candidates pre-filtered by a float model and the best 120 counted
by the evaluator. Best five by score all have round 0 near 120 and round 1 between 170 and 176.

| | Bytes | Opcodes | Work | Security | Tries per spend |
| --- | ---: | ---: | ---: | ---: | ---: |
| `paper-two-round` | 9,349 | 199 | 2^46.740 | 81.521 | 3.5 |
| `late-pools` | 9,293 | 199 | 2^46.081 | 81.521 | 3.5 |
| this | 10,929 | 199 | 2^45.777 | 81.524 | 1.9 |

Score 119,256,975. It does not dominate `late-pools`: 0.3 bits less work for 1,636 bytes more.

What did not work:

- **Both rounds large.** Two rounds of 2^44 selections are 80.8 bits.
- **Dropping the pinning puzzles** and making up the level with selections. Without pinning the
  stored-digest attack caps the level at the sum of the round puzzles, 80.0 bits.
- **A cheap scarce round next to an expensive plentiful one** (32-bit and 40-bit puzzles). The
  first version of the model accepted it at 81.8 bits and a sixteenth of the baseline's score.
  It is 72 bits: seven transactions in eight are abandoned after the cheap round, by the
  attacker as much as by the spender. The model was corrected and the design is now a test.
- **More selections per round** to shrink the pools. Each costs 11 operations and the budget
  is 201; 9 and 8 does not fit with pinning.

## Result and next steps

Work is now 2^45.78: the three pinning puzzles solved once are 15% of it, the `SIGHASH_ALL`
puzzle repeated per try 10%, round 0's search 16% and round 1's 59%. Round 1's attempts cost 32
compressions, 19 of them round 0's pool. That is the next thing to remove, and it needs a way
to keep one round's pool out of the other's sighash tail.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
