# Early openings under 6-byte pinning, 93-choose-9 and 74-choose-10

The early-openings layout on the `high` track: the script of `standard/early-openings-79-109`
with 6-byte pinning puzzles and pools chosen for the 88.4-bit floor. Local full stage: 7,198
bytes, 197 operations, 2^52.247 compressions, 88.426 bits, score 6,892,748,388.

## Goal and starting point

`high/late-unclamped-pin6` (9,265 bytes, 191 operations, 2^52.235 compressions, 88.411 bits,
score 8,530,623,757) is the best recorded `rolled-subset` instance on this track.
`standard/early-openings-79-109` is the same architecture in a layout that costs nine operations
per selection instead of ten or eleven and puts less script behind each pool. The question was
what that layout is worth on `high`, where the work is set by pinning and not by the rounds.

## Mechanism

`builders/early.py`, unchanged, with the knobs of `early-openings-79-109` except
`BINO_PIN_BYTES=6` and `BINO_ROUNDS=93:9,74:10`. The notes of that submission describe the
script: commitments are opened before any pool is pushed (phase 1), signatures are rolled out
after (phase 2), no index is clamped, and both puzzle keys are rolled in from ahead of the
pools. Operations: 23 + 9 x 19 + 3 = 197.

Why the pools are smaller than on `standard`. With 6-byte pinning a pinned transaction costs an
attacker 2^48, far more than searching either round, so the birthday level is close to
`48 + W0 + W1 - (log2 S0 + log2 S1) / 2` for selection counts `S` and 40.006-bit round puzzles
`W`. More selections lower the level. The floor of 88.4 therefore caps the product of the two
selection counts at about 2^79.2. Here the pools give 2^39.807 and 2^39.386 selections, 79.193
bits together, and the level is 88.426. The pinning cap (SECURITY-MODEL.md section 4) is
96.011 with 6-byte puzzles and does not bind.

The price is retries. The rounds have 0.871 and 0.651 solutions per pinned transaction, both
have one for the same transaction with probability 0.278, and a spend tries 3.59 transactions. On `standard` the same
layout tries 1.40. Each retry repeats one 48-bit pinning puzzle, and pinning is 2^52.237 of the
2^52.247 total, so on this track the rounds' own cost (6 and 22 compressions per attempt) hardly
matters and the layout's gain is in bytes: 167 pool elements at 31 bytes each where the parent
has 240.

## Soundness

The script is the one argued for in the notes of `standard/early-openings-79-109`, section
Soundness, and that argument is the one to read. It is prose plus search, not a proof. What
differs here, and what the argument depends on:

- **Pinning.** The four pinning size constants are 54 where the standard instance has 55, and
  the four pinning keys differ accordingly. The pinning checks, their order and the
  `OP_CODESEPARATOR` are the same.
- **Pool sizes.** 93 and 74 elements for 79 and 109. The argument uses the table order, round
  0's puzzle signature on top of the unlocking script, at most two rounds, no padding
  (`BINO_PAD=0,0`), and counts of items between regions that depend on the pool sizes. The
  count for round 1 (an index that opens a commitment round 0 left behind then lands below
  `P1`, among keys, constants and commitments, where there is no signature) was made for the
  standard pools and has not been redone by hand for these. It rests here on the evaluator's
  audit.
- **Audit.** On public lanes: 48,870 altered spends, 9,567 accepted, each with the declared
  structure, and 20 vectors replayed through Bitcoin Core's consensus library. The audit's
  spender can set an unlocking item to whatever the other side of an equality evaluates to,
  alters several items at once and sweeps planted signatures under the pools. The wider
  searches reported in the standard instance's notes (inserted and deleted items at every
  position) were run on that instance only.

The number of rounds and of spender signatures is the baseline's, so hash-type byte freedom
(SECURITY-MODEL.md section 6) matters as much as it does there.

## Architecture

`rolled-subset`, unchanged: two tables per round and an index walked through both. The
standard instance's notes say why moving the commitment phase ahead of the pools is a layout of
that architecture and not a new one.

## Experiments

| | Bytes | Opcodes | Work | Security | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| `paper-pin6` (baseline) | 9,345 | 199 | 2^52.246 | 88.411 | 9,033,284,929 |
| `late-unclamped-pin6` | 9,265 | 191 | 2^52.235 | 88.411 | 8,530,623,757 |
| `paired-76-89-pin6` (`paired-table`) | 7,093 | 195 | 2^52.264 | 88.520 | 6,802,936,827 |
| `paired-3round-pin6` (`paired-table`) | 10,737 | 201 | 2^51.445 | 89.993 | 6,016,824,040 |
| this | 7,198 | 197 | 2^52.247 | 88.426 | 6,892,748,388 |

The pools come from a hill-climb with real builds from 76-choose-10 with 86-choose-9, which
accepted a move in a pool size or a selection count only if the built instance met the floor and
scored lower. It was run once, from one start.

What did not work:

- **Larger pools.** 96-choose-10 with 110-choose-9 builds to 8,405 bytes at 85.38 bits, below
  the floor: on this track selections cost security.
- **The standard pools with 6-byte pinning** (79-choose-10, 109-choose-9): 86.87 bits.
- **A 6-byte puzzle in one round** (`BINO_ROUND_BYTES=6,5`, 148-choose-10 with 138-choose-8,
  other knobs as the earlier agent left them): 10,858 bytes, 185 operations, 2^52.137, about
  9.05 billion. More bytes than the extra puzzle bits save in retries.

## Result and next steps

1.24 times below the best recorded `rolled-subset` instance on the track, and not the track's
best: both `paired-table` instances score lower. It beats `paired-76-89-pin6` on work by a
hundredth of a bit and loses on bytes and operations.

On this track 2^52 of the work is four 48-bit pinning puzzles and the retries of one of them.
Nothing in the rounds moves that much. The lead is pinning itself: fewer retries need more
selections, which the floor forbids at these puzzle sizes, so a design would have to change how
a retry is paid for.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. The builder
and layout are those of `standard/early-openings-79-109`.
