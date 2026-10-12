# Paired tables, three rounds (32, 24 and 32 bits) under 5-byte pinning

Three rounds of small puzzles in place of two 40-bit ones, in a script organised so that a
selected element costs nine operations instead of eleven. Local full stage with the Bitcoin
Core replay: 10,741 bytes (locking 9,319, unlocking 1,422), 201 operations, 2^43.505
compressions, 80.011 bits under BH-SEC-2 against a floor of 80.0, score 24,510,429. That is
4.0 times below `late-unclamped-124-107` (97,605,646), the best recorded instance of the track,
5.0 times below `late-unclamped` (123,217,063), which this builds on, and 8.1 times below the
baseline `paper-two-round` (198,865,940). Local numbers are claims; the judge's run is the
result.

Two things a reader should know before the rest:

- The script has no index clamp. The argument that it does not need one is in the Soundness
  section. It is prose plus search, and it needs a maintainer's reading.
- The design has three rounds, and the security model leaves out an effect (hash-type byte
  freedom) that may count against designs with more rounds. See "Model slack".

## Goal and starting point

`standard/late-unclamped` and the negative result "three rounds do not fit 201 operations and
10,000 bytes together". On this track the pinning cap sets the level of every instance with
5-byte pinning whose rounds are worth at least 80.0 bits, so round parameters trade bytes
against retries. Two 40-bit rounds of 120-choose-8 have 0.76 solutions per transaction each and
the spender tries 3.5 transactions per spend. With puzzles totalling 88 bits (32 + 24 + 32) and
92.06 bits of selections, every round is plentiful (2.3 to 2.8 solutions per transaction) and
the spender tries 1.28 transactions per spend. The work then sits close to what 5-byte pinning
alone costs: `score.json` attributes 2^43.445 of the 2^43.505 to the pinning puzzles, so the
rounds are about 4 percent of the work. The obstacle was the opcode budget: 92 bits of
selections need 19 selected elements over three rounds.

## Mechanism

`builders/pairs.py`. Per round, one table in which each pool signature is pushed directly before
its own commitment. On the stack the commitment of an element is exactly one item above its
signature. A selection is:

    <d> ROLL            index k, from the top of the unlocking script
    DUP PICK            copy of the item k-1 below: the commitment
    <d> ROLL            preimage, from the top of the unlocking script
    HASH160 EQUALVERIFY
    ROLL                the item k below: the signature

`OP_PICK` sees one item less deep than the `OP_ROLL` that follows, because the index is still on
the stack for the first and gone for the second. No `<n> MIN`, no `<c> ADD`: 7 operations, 9
with the key roll and the key. Unselected commitments are never moved; a selected element
leaves its commitment behind.

Each round but the first pushes its puzzle's size constant *before* its table (the "marker")
and, for the puzzle's size check, fetches it with a constant-depth `OP_PICK` (one operation per
round). The unlocking script is consumed strictly from its top, each item by a roll at a
constant depth `d`. Rounds run in the order listed and the script has no `OP_CODESEPARATOR`.

Operations: 13 pinning + 3 x 5 + 2 markers + 19 x 9 = 201.

## Soundness

The claim: every unlocking script the script accepts has, in each round, `t` distinct
signatures of that round's pool, each taken while its own commitment was opened by an
unlocking item, and a puzzle signature from the unlocking script whose size was compared with
the round's declared constant. The claim is about every unlocking script, not only the audited
ones. Since the audit now lets the spender set an unlocking item to the hash of a script
constant, and since an all-unclamped copy of the `late` layout was shown unsound by a fetch
that lands one item off at the end of a round, the argument below was re-read against that
pattern, fetch by fetch, for the first round and for later ones, and for the last slot of each.

Notation. W is the part of the unlocking script not yet consumed, at the bottom of the stack.
A *fetch* is `<d> ROLL` with the constant `d` equal to the number of items the script expects
above the top of W; it returns the top of W exactly when that expectation holds. In a
selection, X is the item `DUP PICK` copies, P the item the second fetch returns, and Y the item
the final `ROLL` takes.

1. **What X can be.** `EQUALVERIFY` passes only if X equals a HASH160 output, 20 bytes. X is
   therefore a commitment of some table on the stack, or an unlocking item that the spender has
   set to `HASH160(P)`. The second case is always available, whatever P is, a script constant
   included. X is not the index itself (at most 4 bytes, or `PICK` fails), the dummy (empty),
   a pool signature (9 bytes) or a marker (1 byte). The equality alone therefore excludes
   nothing below the table; the next two points do.
2. **What Y can be.** Y is the item directly below X when P came from below X, which is the
   case whenever X is in a table. If X is an unlocking item, P came from above it and Y is the
   second item below X, also an unlocking item. So: for X = `c_j` in the round's own table, Y
   is `s_j`; if `s_j` was already taken, Y is the next item down, which is `c_(j+1)`, or for the
   deepest pair the marker (later rounds) or the top of W (first round). For X a commitment
   left by an earlier round, Y lies below the marker. For X in W, Y is in W.
3. **First round to run (no marker): Y is never taken from W.** Suppose a selection takes Y
   from W. That happens in two ways: X in W, or the last slot of the table (X = `c_(n-1)` after
   `s_(n-1)` was taken, so that Y is the top of W). The stack above W is then one item taller
   than every later constant assumes, and the next fetch returns the deepest item of the table
   in place of the top of W: `s_(n-1)` or `c_(n-1)`, 9 or 20 bytes. The next fetch after a
   selection's final `ROLL` is never a preimage fetch. It is the next selection's index, which
   `PICK` reads as a number and refuses above 4 bytes, or, after the last selection, the puzzle
   signature, whose size is compared with the round's own constant (56 in the production
   script, 59 in the test twin; neither is 9 or 20, and both operands are script-determined, so
   the spender has nothing to set). The script fails in both cases. This is the misaligned
   fetch that broke the unclamped `late` variant: there the fetch that followed a misalignment
   could land a commitment fetch on an unlocking item and a preimage fetch on a constant. Here
   a misalignment arises only at the end of a selection, and the fetch that follows it is an
   index or a signature, whose landing place is a table constant of the wrong length.
4. **Later rounds (marker): Y is never taken from at or below the marker.** Count the items
   above the marker. Every fetch takes its item from below the marker (from W, or after a
   misalignment of at most `t` items from the bottom of the earlier rounds' leftovers, which
   hold at least `2n - t` items) and adds one above it, as expected. A final `ROLL` that takes
   Y from above the marker leaves the count as expected. One that takes Y from at or below the
   marker (the marker itself, a pair an earlier round left, W) leaves one more than expected,
   and nothing in the round takes an item away again. With `e >= 1` such rolls, the
   constant-depth `PICK` of the size check returns the `e`-th item from the bottom of the
   table and not the marker. The table keeps at least `2n - t >= t >= e` items, each a script
   constant of 9 or 20 bytes. `EQUALVERIFY` compares it with the result of `OP_SIZE`, a number
   of one byte. Neither operand is an unlocking item, so nothing can be set to make them
   equal, in the production script or in the test twin. The script fails. So every Y, and X
   directly above it, lies above the marker, no Y came from W, every fetch of the round
   returned the top of W, and the `PICK` returned the marker itself, which is the round's
   declared size constant. A selection from another round's leftover pairs (the selection the
   audit found in the unclamped `late` variant) is excluded by this point: it raises the count
   by one.
5. **Hence the `t` selections are pool elements of this round, each opened.** By points 3 and
   4, X and Y lie in the round's table or above it. Above the table are only the script's
   `OP_0`, the items earlier selections put there and, briefly, the index. The multisig takes
   the `t + 1` items above the dummy as signatures and requires an empty dummy. There are
   `t + 1` items above the script's `OP_0` only if all `t` final rolls took their Y from the
   table (a roll of an item that was already above the table adds none). Otherwise the multisig
   reaches one item further down: it checks the empty `OP_0` as a signature, which fails a
   `(t+1)`-of-`(t+1)` multisig, and takes a table constant as its dummy, which is not empty. So
   all `t` items came from the table, and each must be a strictly encoded signature. The
   table's only such items are the pool signatures (commitments are not signature-shaped, and
   the evaluator refuses an instance with any undeclared signature-shaped push). By point 2 a
   pool signature `s_j` is taken only while directly below X = `c_j`, so `HASH160(P) = c_j`
   with P an unlocking item (the fetch was aligned). `s_j` leaves the table when taken, so the
   `t` elements are distinct.
6. **The puzzle signature.** The fetch after the last selection is aligned, so it returns an
   unlocking item. Its size is compared with the declared constant (the script constant in the
   first round, the marker in later ones). It is the top signature of the multisig and the
   puzzle key is the top key, so with `t + 1` of `t + 1` it is the signature verified under the
   puzzle key.
7. Pinning, the `SIGHASH_SINGLE` check, pools and commitments are of the kind `late.py` emits;
   every selection of `C(n, t)` is reachable (a selection is listed deepest element first,
   which restricts order, not the set).

What the argument depends on: `n > t` in every round; 9-byte pool signatures and 20-byte
commitments that are not signature-shaped (checked for this specimen; a deployment must check
its own commitments); size constants of one byte that are neither 9 nor 20; no conditional
execution, so that the size check of every round always runs; the first table lying directly
on the unlocking script.

Searches, none of which is a proof:

- **The evaluator's audit**, public lanes, full stage: 74,943 altered spends, 7,244 accepted,
  all with the full structure; Core replay of 20 vectors agrees.
- **An exhaustive search on an abstract stack machine**, written for this re-read and not part
  of this pull request. It executes the script built by `pairs.py` (the test twin and the
  production script, at the submitted parameters) with every unlocking item free: an item
  becomes a number when the script uses it as one, branching over every depth of the stack,
  and otherwise counts as whatever bytes the check at hand needs (a signature of the right
  size, the hash of the other operand, a preimage of a commitment, a key). Signature checks
  pass whenever the spender supplies the signature or the key. It judges accepted executions by
  the evaluator's structure rule. Result, with four spare items under the unlocking script:
  27.6 million branches, 384 accepted executions, all of the honest shape, none after an index
  that pointed anywhere but at a pair of the round's own table. Two reductions were used and
  are the limits of this search: among targets of the same kind (a commitment with its own
  signature directly below it) only the shallowest and the deepest of each table were
  continued, and only the shallowest once a path had left the honest shape; and a constant
  that is not a signature was rejected when taken as a selection instead of at the multisig
  (on tables of 11 and 12 elements the search with and without this shortcut accepts the same
  executions). As a check of the search itself, the same builder with the markers removed is
  found unsound at once (a round takes a pair the previous round left).
- **Concrete altered spends through `bh.interp.verify`** in oracle mode on the test twin, with
  a pad of 142 full-size (59-byte) signatures planted under the unlocking script, so that a
  misaligned puzzle-signature fetch finds an item that passes a size check, which the audit's
  9-byte plants do not: every index at every depth (13,623 spends, 953 accepted), then 39,694
  sampled spends with two or three consecutively consumed indexes moved at once and up to two
  other items replaced by a signature, a size, a number or nothing. Of those, 526 were accepted, none without
  the structure.

I found no accepted unsound spend and no case the seven points do not cover. That is a prose
argument and three searches. A maintainer should read points 1 to 6 before this instance is
relied on, and a variant of the layout (a marker round whose table could shrink below `t`
items, a size constant of 9 or 20, a commitment hash whose outputs could be signature-shaped,
anything placed between the first table and the unlocking script) would need the argument
made again.

## Model slack

- **The level is the pinning cap.** BH-SEC-2 counts this instance, like every recorded standard
  instance, at 80.011 bits: the cost of serving two 5-byte pinning puzzles with one signature
  mode. Before the cap, the model's own search (`bh.model._level`, as `uncapped` in
  `tests/test_model.py`) prices its rounds at 82.019 bits; stored digests cost at least the 88
  bits of the three round puzzles. For comparison the rounds of `late-unclamped` are worth
  81.521 and those of `late-unclamped-124-107` 81.126. The first search evaluated a slightly finer partial-search attacker by hand at
  82.006 for this instance; that figure is not recomputed here. Partial search is now part of
  the model.
- **Pinning is 5 bytes**, as in the baseline, so assumption A2 is used exactly as the baseline
  uses it. The builder's default of 4-byte pinning is not a way around anything: the cap prices
  it at 64.011 bits and the track refuses it.
- **Three round signatures instead of two.** A downstream verifier must check one more
  hash-type byte (assumption A3).
- **Hash-type byte freedom is outside the model, and it concerns this instance
  specifically.** Any of 256 hash-type bytes is consensus-valid and each gives a different
  sighash (SECURITY-MODEL.md, section 6). The paper prices this at under one bit for its
  configuration. A two-sided birthday estimate from the first search puts it near 4 bits per
  round beyond the first. If that estimate is right, a three-round instance is weaker than a
  two-round one at equal `security_bits`, by about 4 bits here, and this instance's advantage
  over two-round designs is partly an artefact of what the model omits. The two figures have
  not been reconciled. Nothing in this design changes how much the effect matters per round;
  it only has one more round than the instances it is compared with.

## Architecture

`paired-table`, new. One table of adjacent pairs per round instead of two tables; one index
used by `PICK` and `ROLL` at depths that differ by construction; out-of-pool selections
excluded by adjacency and one height check per round, not a clamp per selection. No change of
`rolled-subset` knobs produces it. The starting board lists "interleaved as pairs" as negative
because the second fetch is off by one; fetching the commitment with `PICK` and leaving it in
place is what absorbs that.

## Experiments

Counts from the current evaluator. "Rounds alone" is the level before the cap, from
`bh.model._level`. The first two rows are the ledger's and the last is this full-stage run; the
others are counted with `Judge.count` without lanes.

| | Bytes | Opcodes | Work | Security | Rounds alone | Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `late-unclamped` (recorded) | 9,269 | 191 | 2^46.121 | 80.011 | 81.521 | 123,217,063 |
| `late-unclamped-124-107` (recorded) | 9,067 | 201 | 2^45.743 | 80.011 | 81.126 | 97,605,646 |
| 105:9, 74:10, puzzles 5,5 bytes (this builder, two rounds) | 7,531 | 195 | 2^46.222 | 80.011 | 81.150 | 109,621,538 |
| 92:5, 98:7, 98:7, puzzles 3,4,4 | 11,020 | 201 | 2^43.559 | 80.011 | 81.593 | 26,106,185 |
| 96:7, 96:7, 87:5, puzzles 4,4,3 | 10,741 | 201 | 2^43.528 | 80.011 | 82.007 | 24,904,315 |
| this: 96:7, 88:5, 95:7, puzzles 4,3,4 | 10,741 | 201 | 2^43.505 | 80.011 | 82.019 | 24,510,429 |

A hill-climb with real builds from these pools (one step in `n` or in `t` of a round, and
moving a selection from one round to another) found no lower score. Started from puzzles of
4,4,4 bytes it found none either (that start is itself invalid), nor from two rounds of 5,5
bytes with this builder; the best two-round point is the third row above.

What did not work:

- **Two rounds with this builder.** Smaller and under the opcode limit, but the work stays at
  2^46.2 because each 40-bit round is scarce: 4.5 times the score of the three-round instance.
- **4-byte pinning.** 2^39.016 compressions, 22 times less work, and refused: the cap prices it
  at 64.011 bits.
- **No pinning, five or six small rounds.** Measured in the first search under the old model:
  without pinning nothing dominates a transaction's cost, and an attacker who searches part of
  a round, the attacker BH-SEC-2 now assumes, pays about 73 bits against five balanced 24-bit
  rounds. Not submitted and not measured again.
- **A scarce "gate" round with two selections** as a fine difficulty knob: the judge cannot
  grind its test twin, and it is the scarce-round slack the model was corrected for.
- **Four rounds under pinning.** The opcode budget allows 18 selections at most; in the first
  search that was about 5 bits of selections short.
- **Other splits of 19 selections** needed, in the first search, a pool of over 140 elements
  and more than 10,000 bytes of locking script.
- **Interleaving the three tables** to cut compressions per attempt: not worth it here, since
  the rounds are about 4 percent of the work.

## Result and next steps

10,741 bytes, 201 operations, 2^43.505 compressions, 80.011 bits (rounds alone 82.019), score
24,510,429 on public lanes. The work is within 0.06 bits of its pinning share, so what is left
on this track for this design is bytes times operations. It uses all 201 operations, so
nothing is left for an application. One operation fewer per selected element would free 19
operations, enough for two more selections and smaller pools.

Caveats, in order of weight: the soundness argument has not been read by anyone but its
authors; the hash-type question above may count against three rounds; the rounds have 2 bits
of slack above the floor that the cap hides, and a contract that removed the cap would rank
this instance by 82.019 and not by 80.011.

The first search's finding that BH-SEC-1 mispriced partial search of an oversized round is
fixed in BH-SEC-2 (SECURITY-MODEL.md, section 8).

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. The design
and builder come from the first search under BH-SEC-1; this submission re-measures it under
BH-SEC-2 and re-reads its soundness argument against the corrected audit. Builds on the notes of
`late-unclamped` (the shift argument for an unclamped first round).
