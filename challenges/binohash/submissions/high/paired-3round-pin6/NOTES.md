# Paired tables, three rounds (32, 24 and 32 bits) under 6-byte pinning

`standard/paired-3round-pin5` with 6-byte pinning puzzles, which is what the `high` track needs.
Local full stage with the Bitcoin Core replay: 10,737 bytes (locking 9,319, unlocking 1,418),
201 operations, 2^51.445 compressions, 89.993 bits under BH-SEC-2 against a floor of 88.4, score
6,016,824,040. That is 29% below `late-unclamped-pin6` (8,530,623,757), the lowest recorded score
of the track, and 33% below the baseline `paper-pin6` (9,033,284,929). Local numbers are claims;
the judge's run is the result.

Two things a reader should know before the rest:

- The script has no index clamp. The argument that it does not need one is the one in the notes
  of `standard/paired-3round-pin5`. It is prose plus search, and it needs a maintainer's reading.
- The design has three rounds, and the security model leaves out an effect (hash-type byte
  freedom) that may count against designs with more rounds. See "Model slack".

## Goal and starting point

`standard/paired-3round-pin5`, the first instance of the `paired-table` architecture, and the
`high` track, which has no instance of that architecture. On `high` every recorded instance is
two rounds of 120-choose-8 under 5-byte round puzzles: each round has 0.76 solutions per pinned
transaction, both have one with probability 0.28, and the spender tries about 3.5 transactions
per spend, each at the price of a 2^48 pinning puzzle. The standard instance's three rounds are
plentiful (2.3 to 2.8 solutions each), so the question was whether the same rounds clear the
`high` floor once pinning is 6 bytes, and what they cost there.

5-byte pinning is not an option on this track: the pinning cap is then 80.011 bits, below the
floor. With 6-byte pinning the cap is 96.011 and does not bind, so the level is the rounds'.

## Mechanism

`builders/pairs.py`, unchanged, with the standard instance's rounds and `BINO_PIN_BYTES=6`. Each
round is one table of (signature, commitment) pairs; a selection is one index used by `DUP PICK`
for the commitment and by `ROLL` for the signature directly below it; every round but the first
keeps its puzzle's size constant under its table as a height marker. The script and its
operation count are described in the notes of `standard/paired-3round-pin5`.

The only difference from that instance in the locking script is in the pinning part, its first
200 bytes: the size constant of the four pinning puzzles is 54 where the standard instance has
55, and the four pinning keys are the ones whose targets suit that size. Every byte after the
pinning part is the same, and the locking script has the same length, 9,319 bytes. The unlocking script is 4 bytes shorter (1,418 against 1,422), one byte per pinning
signature.

Operations: 13 pinning + 3 x 5 + 2 markers + 19 x 9 = 201.

What it does to the counts, from `score.json`:

- **Work.** Each round has a solution with probability 0.937, 0.902 and 0.923, all three with
  0.780, so the spender tries 1.28 transactions per spend against about 3.5 for the recorded
  instances. Pinning is 2^51.4446 of the 2^51.4448 compressions; the rounds are under 0.02
  percent of the work. That is 0.79 bits below the 2^52.235 of `late-unclamped-pin6`.
- **Bytes and operations.** Both are higher than every recorded instance of the track: 279 pool
  elements in place of 240, and all 201 operations.

## Soundness

The argument is the seven points of the Soundness section in the notes of
`standard/paired-3round-pin5`. It is not repeated here. It is about the stack behaviour of the
selection and marker code and about the lengths of the constants in the tables, and none of
that differs: this locking script is the standard instance's with the four size constants and
the four keys of the pinning part changed (compared byte by byte from the two builds). The
pools, the commitments, the three round puzzles and the selection code are byte for byte the
same.

That argument lists what it depends on. Checked for this instance, from the built script:

- `n > t` in every round: 96 > 7, 88 > 5, 95 > 7. The form the argument uses (point 4) is
  `2n - t >= t`, the number of items a table keeps against the number of rolls that could go
  wrong: 185, 171 and 183 against 7, 5 and 7.
- Pool signatures are 9-byte pushes and commitments 20-byte pushes, in all three tables.
- The round size constants are one byte each and neither 9 nor 20: 56, 57 and 56 in the
  production script, 59 in the test twin. The pinning size constant, 54, is not used by the
  argument; pinning runs before any table is on the stack and is the code `late.py` emits.
- No conditional execution, and the first table lies directly on the unlocking script.

What 6-byte pinning changes for security is in the model and not in the script's structure: the
four pinning puzzles still have pairwise disjoint sighash targets and the `SIGHASH_SINGLE` check
is unchanged, which the evaluator checks before it credits pinning.

Search, which is not a proof: the evaluator's audit on public lanes, full stage, tried 74,943
altered spends and accepted 6,691, every one with the declared structure, and the Core replay of
20 vectors agrees. The exhaustive abstract-machine search and the padded concrete search
described in the standard instance's notes were run on that instance. They were not run again
for this one; they apply to the extent that the two scripts differ only in the pinning part.

A maintainer should read points 1 to 6 of the standard instance's argument before either
instance is relied on.

## Model slack

- **The level is the rounds', not the cap.** 89.993 bits, 1.593 above the floor. With pinning
  at 2^48 per transaction dominating an attacker's cost, the level is about
  `48 + (32 + 24 + 32) - (33.47 + 25.22 + 33.36) / 2 = 89.99`. The same rounds under 5-byte
  pinning are worth 82.019 before the cap; the 8 bits are the pinning puzzle.
- **The margin cannot be spent cheaply.** More selections lower the level here, and 3.2 more
  bits of selections would bring it to the floor, but they need larger pools or a further
  selected element, and the script already uses all 201 operations. Puzzles come in whole bytes,
  so a round cannot be made slightly easier instead.
- **Three round signatures instead of two.** A downstream verifier must check one more
  hash-type byte (assumption A3).
- **Hash-type byte freedom is outside the model, and it concerns this instance specifically.**
  Any of 256 hash-type bytes is consensus-valid and each gives a different sighash
  (SECURITY-MODEL.md, section 6). The paper prices this at under one bit for its configuration.
  A two-sided birthday estimate from the first search puts it near 4 bits per round beyond the
  first. If that estimate is right, a three-round instance is weaker than a two-round one at
  equal `security_bits` by about 4 bits, which is more than this instance's 1.593 bits of margin
  over the floor, and its advantage over the recorded two-round instances is partly an artefact
  of what the model omits. The two figures have not been reconciled. Nothing in this design
  changes how much the effect matters per round; it has one more round than the instances it is
  compared with.

## Architecture

`paired-table`, unchanged. The builder and the registry entry are those recorded with
`standard/paired-3round-pin5`; this pull request adds no code. It is the first instance of the
architecture on this track.

## Experiments

The first three rows are the ledger's; the last is this full-stage run on public lanes.

| | Bytes | Opcodes | Work | Security | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| `paper-pin6` (baseline) | 9,345 | 199 | 2^52.246 | 88.411 | 9,033,284,929 |
| `late-pools-pin6` | 9,289 | 199 | 2^52.235 | 88.411 | 8,910,950,604 |
| `late-unclamped-pin6` | 9,265 | 191 | 2^52.235 | 88.411 | 8,530,623,757 |
| this: 96:7, 88:5, 95:7, puzzles 4,3,4 | 10,737 | 201 | 2^51.445 | 89.993 | 6,016,824,040 |

    python3 challenge.py run binohash challenges/binohash/submissions/high/paired-3round-pin6 -- --core tools/core/target/release/cchk
    OK  reference-48+core-20: 48 lanes, 74943 altered spends (6691 accepted, all sound)

What did not work:

- **5-byte pinning.** Capped at 80.011 bits, below the floor. This is the track's known negative
  result and the reason this is a separate instance.
- **Other pools and selection counts.** A hill-climb with real builds over pool sizes and
  selection counts, started from these pools, found no lower score.
- **Round puzzles of 4,4,4 bytes.** The best point such a climb found was 105:6, 104:6, 91:7 at
  11,387 bytes and 2^53.540 compressions, a score of about 27.3 billion: 4.5 times this one.
  The scarcer rounds cost retries at 2^48 each.

## Result and next steps

10,737 bytes, 201 operations, 2^51.445 compressions, 89.993 bits, score 6,016,824,040 on public
lanes. It trades bytes and operations for work: larger than every recorded instance of the
track and with no operation left for an application, and 0.79 bits less work. The work is
pinning, tried 1.28 times, so a design of this kind has at most 0.36 bits of work left to gain
on this track; what remains is bytes times operations and the 1.593 bits of level above the
floor that this instance does not use.

Caveats, in order of weight: the soundness argument has not been read by anyone but its
authors; the hash-type question above may count against three rounds and, if the larger
estimate holds, by more than this instance's margin over the floor.

A two-round instance of the same architecture, without the three-round caveat, is submitted
separately as `high/paired-76-89-pin6`.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. Builds on
`standard/paired-3round-pin5` (the builder, the mechanism and the soundness argument).
