# Scoring

## The score

Each challenge defines one scalar score, lower is better, in its `benchmark.json`. For
Binohash:

    score = bytes x opcodes x 2^(work_bits - 40)

- `bytes`: the production locking script plus the largest honest unlocking script.
- `opcodes`: the interpreter's operation count for the locking script on an honest spend.
- `work_bits`: log2 of the expected SHA-256 compressions for one honest spend; the score counts
  work in units of 2^40 compressions.

All three are computed by the trusted evaluator from the instance itself. They are exact:
the same instance gives the same counts under every seed.

A product treats a given percentage saved on any axis the same. That is a deliberate, neutral
choice, not a cost model: halving the work, halving the bytes and freeing half the opcode
budget are different kinds of gain for different users. The front below is what keeps the
choice from deciding everything.

## What is held fixed

Each track fixes a **security floor**. The evaluator computes an instance's security level from
its script under the challenge's security model, and refuses the instance if the level is
below the floor. Security is not scored: an instance far above the floor earns nothing for it.
The floor of each Binohash track is the level of a published configuration as the evaluator
counts it. The model, its assumptions and what it leaves out are part of the challenge's spec.

## The baseline

Each track names a baseline in `benchmark.json`: the construction the challenge starts from,
built with its published parameters and validated by the same evaluator as every other row.
For Binohash that is the script of the Binohash paper. The baseline is an ordinary ledger row,
so "how far below the baseline" compares like with like. The paper's own figures are kept in
`targets.json` with their conventions.

A staging track can instead name a pending baseline candidate in its starting-board catalogue
until a judge run under the ledger key records it. It has no recorded baseline score or "below
baseline" percentage during that interval. Pending baselines cannot be used on live tracks.

## What gets recorded

A validated instance is recorded in the ledger when at least one of these holds. Each is named
in the row's `standing` column.

| Standing | Condition |
| --- | --- |
| `new-architecture` | It is the first validated instance of its architecture in the track. |
| `architecture-elite` | Its score beats the best score of its architecture by the margin. |
| `front` | It needs less work, by the margin, than every recorded instance of the track that is no larger in bytes and uses no more opcodes. |

The margin is `acceptance.minImprovementBips` in `benchmark.json` (100 basis points, 1%, for
Binohash). The counts are exact, so the margin is not there for noise. It keeps single-step
parameter nudges from filling the board.

The same instance, byte for byte, is never recorded twice.

## Why not a single best score

A single leaderboard number rewards only whatever beats the incumbent. Two things are lost:

- **New designs.** An architecture that is not yet competitive is where the next large gain
  usually comes from. `new-architecture` and `architecture-elite` keep every design's best
  instance on the board, so it can be improved.
- **Trade-offs.** A script with 60 free opcodes and more grinding can be the right one for a
  protocol that needs room for its own logic, and one that is 3 kB smaller the right one when
  fees dominate. `front` records every advance of the three-way front, whatever it does to the
  product.

So the leaderboard has two levels. The primary one lists architectures, each with its elite.
The secondary one lists the instances within an architecture. The headline number of a track is
still its lowest score, read against the track's baseline.

## Reading order for a search

1. Find which count limits the use you care about, and which part of the script sets it.
2. Explore: is there a different organisation that removes the limit? That is a new
   architecture ([ARCHITECTURES.md](ARCHITECTURES.md)).
3. Exploit: tune the best design. Check what the security formula does to each parameter before
   moving it; a saving that drops the level below the floor is not a saving.

## Published targets

`targets.json` lists published points for context, with their conventions. They are not ledger
rows: a published figure is not an instance the evaluator has passed. Where a target's
accounting differs from the evaluator's, the file says how to read one against the other.
