# Paired tables, two rounds of 5-byte puzzles (76-choose-10, 89-choose-9) under 6-byte pinning

A two-round `paired-table` instance for the `high` track, and the smallest script recorded on it.
Local full stage with the Bitcoin Core replay: 7,093 bytes (locking 5,735, unlocking 1,358), 195
operations, 2^52.264 compressions, 88.520 bits under BH-SEC-2 against a floor of 88.4, score
6,802,936,827. Local numbers are claims; the judge's run is the result.

Three things a reader should know before the rest:

- It is not the lowest score of its architecture on this track. `high/paired-3round-pin6`,
  submitted separately, scores 6,016,824,040 locally. This instance is 2,172 bytes smaller than
  the smallest recorded instance of the track and has two rounds, so the open question about
  three-round designs does not apply to it. See "Result and next steps" for the rule under
  which it qualifies.
- It needs slightly more work than the recorded instances, not less: 2^52.264 against 2^52.235.
- The script has no index clamp. The argument that it does not need one is the one in the notes
  of `standard/paired-3round-pin5`. It is prose plus search, and it needs a maintainer's reading.

## Goal and starting point

`standard/paired-3round-pin5`, whose builder spends nine operations per selected element where
the rolled-subset builders spend eleven. The recorded `high` instances are two rounds of
120-choose-8: 16 selected elements and 240 pool elements, which are most of their 9,265 to 9,345
bytes. The goal was a two-round instance with the same puzzles and the same level that uses the
cheaper selection to select more elements from smaller pools.

## Mechanism

`builders/pairs.py`, unchanged, with two rounds and 5-byte round puzzles under 6-byte pinning.
Each round is one table of (signature, commitment) pairs; a selection is one index used by
`DUP PICK` for the commitment and by `ROLL` for the signature directly below it; the second
round keeps its puzzle's size constant under its table as a height marker. The script is
described in the notes of `standard/paired-3round-pin5`.

Operations: 13 pinning + 2 x 5 + 1 marker + 19 x 9 = 195. A twentieth selection would need 204.

What it does to the counts:

- **Bytes.** 19 selections in place of 16 reach the same number of selections from 165 pool
  elements in place of 240. A pool element is 31 bytes of locking script, so the locking script
  is 5,735 bytes. The unlocking script grows to 1,358 bytes with three more selected elements,
  each a key, a preimage and an index.
- **Operations.** 195, four more than `late-unclamped-pin6` and four fewer than the baseline.
- **Work.** 2^52.264, of which pinning is 2^52.241. See the next section for why it does not
  fall.

## The shape of the `high` track

On this track pinning costs 2^48 per transaction and dominates what a transaction costs an
attacker. With `W1`, `W2` the puzzle bits and `S1`, `S2` the selection counts of the two rounds,
the level is then about

    48 + W1 + W2 - (log2 S1 + log2 S2) / 2

so more selections lower it. With two 40-bit puzzles the floor of 88.4 caps the product of the
two selection counts at about 2^79.2. The recorded instances sit at that cap: 120-choose-8 is
39.61 bits, twice that is 79.22, and their level is 88.411.

That makes the rounds scarcer than on `standard`, where the cap sets the level and pools can
grow until every round is plentiful. Here a round has less than one solution per transaction by
construction, and each retry costs a 2^48 pinning puzzle. From this instance's `score.json`:

| Round | Pool | Selection bits | Puzzle bits | Expected solutions per transaction |
| --- | --- | ---: | ---: | ---: |
| 0 | 76-choose-10 | 39.796 | 40.006 | 0.865 |
| 1 | 89-choose-9 | 39.209 | 40.006 | 0.576 |

The two total 79.005 bits. Both rounds have a solution with probability 0.253, and the spender
tries 3.95 transactions per spend, against about 3.5 for 120-choose-8 twice. More tries cost
work; the net difference to `late-unclamped-pin6` is 0.03 bits. The rest is in the compressions
per pinning attempt (2, 2, 3 and 3 here), which depend on the length of the script; it is not
broken down further here. Binomials move in steps: this point has 79.005 bits of selections,
0.23 under the cap, and its level is 88.520, 0.120 above the floor.

## Soundness

The argument is the seven points of the Soundness section in the notes of
`standard/paired-3round-pin5`. It is not repeated here. The selection code, the marker code and
the layout are what that builder emits for any rounds; what differs from the standard instance
is the number of rounds (two, so one marker round in place of two), the pool sizes, the
selection counts and the puzzle sizes. The argument does not use the number of rounds: point 3
covers the round that runs first and point 4 any later round.

That argument lists what it depends on. Checked for this instance, from the built script:

- `n > t` in both rounds: 76 > 10 and 89 > 9. The form the argument uses (point 4) is
  `2n - t >= t`, the number of items a table keeps against the number of rolls that could go
  wrong: 142 against 10 and 169 against 9.
- Pool signatures are 9-byte pushes and commitments 20-byte pushes, in both tables.
- The round size constants differ from the standard instance's, because the round puzzles are 5
  bytes and not 4 or 3: both are 55 in the production script (a constant in the first round, the
  marker in the second) and 59 in the test twin. Each is one byte and neither 9 nor 20, which
  is what points 3 and 4 need of them. The pinning size constant is 54; the argument does not
  use it.
- No conditional execution, and the first table lies directly on the unlocking script.

Pinning is the four puzzles and the `SIGHASH_SINGLE` check that `late.py` emits, at 6 bytes; the
evaluator checks the disjoint targets before it credits pinning.

Search, which is not a proof: the evaluator's audit on public lanes, full stage, tried 49,326
altered spends and accepted 5,550, every one with the declared structure, and the Core replay of
20 vectors agrees. The exhaustive abstract-machine search and the padded concrete search
described in the standard instance's notes were run on that three-round instance at its
parameters. They were not run for this one.

A maintainer should read points 1 to 6 of the standard instance's argument before this instance
is relied on.

## Model slack

- **The level is the rounds'.** The pinning cap is 96.011 with 6-byte pinning and does not
  bind. 5-byte pinning is capped at 80.011, below the floor.
- **Two rounds.** The hash-type question of SECURITY-MODEL.md, section 6 (whether hash-type
  byte freedom is worth about 4 bits per round beyond the first) bears on this instance exactly
  as on the recorded two-round instances of the track, and not more.
- **Unequal selection counts.** Round 1 has 0.58 solutions per transaction and round 0 has 0.86.
  BH-SEC-2 prices partial search and abandoned transactions, and the 88.520 is its figure for
  these two rounds as they are.

## Architecture

`paired-table`, unchanged. The builder and the registry entry are those recorded with
`standard/paired-3round-pin5`; this pull request adds no code.

## Experiments

The first three rows are the ledger's; the fourth is the local full-stage run of the separate
three-round submission; the last is this full-stage run on public lanes.

| | Bytes | Opcodes | Work | Security | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| `paper-pin6` (baseline) | 9,345 | 199 | 2^52.246 | 88.411 | 9,033,284,929 |
| `late-pools-pin6` | 9,289 | 199 | 2^52.235 | 88.411 | 8,910,950,604 |
| `late-unclamped-pin6` | 9,265 | 191 | 2^52.235 | 88.411 | 8,530,623,757 |
| `paired-3round-pin6` (local, not recorded) | 10,737 | 201 | 2^51.445 | 89.993 | 6,016,824,040 |
| this: 76:10, 89:9, puzzles 5,5 | 7,093 | 195 | 2^52.264 | 88.520 | 6,802,936,827 |

    python3 challenge.py run binohash challenges/binohash/submissions/high/paired-76-89-pin6 -- --core tools/core/target/release/cchk
    OK  reference-48+core-20: 48 lanes, 49326 altered spends (5550 accepted, all sound)

How it was found: a hill-climb with real builds over pool sizes and selection counts, started
from 88:9, 88:9. This is where it ended.

What did not work:

- **Less work with two rounds.** The floor caps the selections, so two 40-bit rounds cannot be
  made plentiful on this track. The work of the two-round instances in the table is the
  pinning puzzles, the per-transaction one tried three to four times.
- **5-byte pinning.** Capped at 80.011 bits, below the floor.
- **Three rounds** have less work and more bytes; that is the other submission, with its own
  caveat.

## Result and next steps

7,093 bytes, 195 operations, 2^52.264 compressions, 88.520 bits, score 6,802,936,827 on public
lanes: 20% below `late-unclamped-pin6` and 25% below the baseline, all of it bytes. It is 13%
above the local score of `paired-3round-pin6`.

On standing, plainly: this is not the best score of its architecture if `paired-3round-pin6` is
recorded first, and it does not need less work than the instances on the board. It qualifies
under the third acceptance rule (`acceptance.rule` in `benchmark.json`, the `front` standing):
it needs less work than every recorded instance that is no larger and uses no more operations,
and there is no such instance. Nothing recorded on the track is within 2,000 bytes of it. If it
is validated before any other `paired-table` instance of the track, it is instead the first of
its architecture there.

Next: the level has 0.120 bits of slack and six operations are free. Neither converts into a
further selection (204 operations). A design that frees one operation per selected element
would allow a twentieth selection and smaller pools again.

Caveat: the soundness argument has not been read by anyone but its authors, and the searches
that accompany it were run on the three-round standard instance, not on this one.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. Builds on
`standard/paired-3round-pin5` (the builder, the mechanism and the soundness argument).
