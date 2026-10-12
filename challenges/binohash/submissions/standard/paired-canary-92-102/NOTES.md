# Paired table under a canary, two 40-bit rounds: 102-choose-9 paired, 92-choose-9 in two tables

A two-round instance of the paired table: 5-byte pinning and two 5-byte round puzzles, as in the
baseline, with no index clamp in either round. Local full stage with the Bitcoin Core replay:
7,954 bytes (locking 6,655, unlocking 1,299), 196 operations, 2^45.746 compressions, 80.011 bits
under BH-SEC-2 against a floor of 80.0, score 83,668,120. Local numbers are claims; the judge's
run is the result.

Three things a reader should know before the rest:

- **It does not beat its architecture's best score.** `paired-3round-pin5` scores 24,510,429.
  This instance asks to be recorded on the other ground of the acceptance rule: no recorded
  instance is both no larger and no heavier in operations, so it extends the track's front. That
  ground is thin: `early-openings-79-109` is smaller, needs less work and scores better, and
  this instance is on the front only because it uses 196 operations against 197. What it adds
  to the board is a paired-table instance with two rounds, which does not carry the
  three-round hash-type caveat (SECURITY-MODEL.md, section 6), and which is 2,787 bytes smaller
  and 5 operations lighter than the architecture's best.
- **The script has no index clamp.** The argument that it does not need one is in the Soundness
  section. It is prose plus search, not a proof, and it needs a maintainer's reading.
- **One of its two rounds is not a paired table.** Round 0 keeps the paper's two tables. See
  Architecture.

## Goal and starting point

`standard/paired-3round-pin5` (architecture `paired-table`, builder `pairs`), whose notes list
"two rounds with this builder" as a negative: 7,531 bytes, 195 operations, 2^46.222, score
109,621,538. A two-round paired instance is small but its work is poor, because a paired pool
spans 31 bytes per element and the pool that lies in front is rehashed by every grinding attempt
of the other round (50 compressions per attempt there).

The builder here was written independently in the first search, under BH-SEC-1, as a design
called `paired`, and tuned to 92-choose-9 twice (7,644 bytes, 196 operations, 2^45.955, score
92,941,649 under the current evaluator). This submission ports it as `canary`, re-tunes the
pools under BH-SEC-2 and re-reads its soundness argument against the corrected audit.

## Mechanism

`builders/canary.py` with `BINO_ROUNDS=92:9,102:9` and `BINO_SPLIT=0`. The last round listed
runs first.

- **Round 1 (102-choose-9) runs first and is a paired table.** Each pool signature is pushed
  directly before its own commitment, and a selection is
  `<d> ROLL DUP PICK <d'> ROLL HASH160 EQUALVERIFY ROLL`: the index, a copy of the item one
  less deep than the index says (the commitment), the preimage, and then the item the index
  names once the index is gone (the signature under that commitment). Seven operations, nine
  with the key roll and the key. This is the selection of `pairs`.
- **Round 0 (92-choose-9) runs last and keeps two tables.** Its 92 commitments are pushed ahead
  of both pools, as in `late`, and its pool is 92 bare signatures at the end of the script. A
  selection is `<d> ROLL DUP <k> ADD ROLL <d'> ROLL HASH160 EQUALVERIFY ROLL`: the paper's loop
  without `<n> MIN`. Eight operations, ten with the key roll and the key. The reason is work:
  with round 0's pool at 10 bytes per element behind it, an attempt of round 1 costs 29
  compressions; with both rounds paired it costs 59 (measured below).
- **The canary replaces the clamp in both rounds.** Before a round pushes its pool, the script
  rolls that round's puzzle signature up from the top of the unlocking script (`<a> ROLL`, one
  operation per round), so that it lies directly beneath the pool and above everything the
  script has left on the stack. After the selections it is fetched at a constant depth and
  size-checked: `<2n+1> ROLL SIZE <size> EQUALVERIFY` for the paired round, `<n+1> ROLL ...` for
  the split one. Any selection that took its item from beneath the pool leaves one item more
  above the canary than the fetch assumes, and the fetch returns a pool item instead.
- Rounds run in the order 1, 0. There is no `OP_CODESEPARATOR`. Each round ends in one
  10-of-10 multisig with the puzzle key last.

Operations: 13 pinning + (9 x 9 + 5 + 1) + (10 x 9 + 5 + 1) = 196. Bytes: 92 commitments
(1,932), 102 pairs (3,162), 92 signatures (920), loops and multisigs and pinning (641);
unlocking 1,299.

What differs from `pairs` (verified by reading both builders):

| | `pairs` | `canary` |
| --- | --- | --- |
| Table and selection of a paired round | pairs, `ROLL DUP PICK ROLL HASH160 EQUALVERIFY ROLL` | the same |
| What lies under a table | the puzzle's size constant (a "marker"), in every round but the first | the puzzle signature itself, rolled there from the unlocking script |
| How it is read back | constant-depth `PICK`, as the size operand | constant-depth `ROLL`, as the item whose size is checked against a constant in place |
| The first round to run | no marker; a separate misalignment argument | a canary too, whenever script items lie beneath its pool (here: round 0's commitment table) |
| Order | rounds run as listed; selections deepest first | last listed runs first; selections shallowest first (paired) or in any order (split) |
| Unlocking script | consumed strictly from its top | per round: puzzle signature on top, then the keys, then indexes and preimages; the keys are the spacing the argument uses |
| Two-table rounds | none | `BINO_SPLIT` |

## Soundness

The claim: every unlocking script the locking script accepts has, in each round, nine distinct
signatures of that round's pool, each taken while its own commitment was compared with the hash
of an unlocking item, and a puzzle signature from the unlocking script whose size was compared
with the round's constant and which is verified under the puzzle key.

The audit lets the spender set an unlocking item to the hash of a script constant, and an
all-unclamped copy of the `late` layout was shown unsound by a fetch that lands one item off: a
commitment fetch on an unlocking item and a preimage fetch on a script constant
(SECURITY-MODEL.md, section 8). The first search's argument for this design was therefore
re-read fetch by fetch for this configuration, both rounds, the last slot of each, and the
canary fetch. It is written out again below, more strictly than before: every unlocking item is
taken to be arbitrary, and an equality with an unlocking item on either side is taken to hold.

Notation. `W` is what is left of the unlocking script, at the bottom. `C0` is round 0's
commitment table (92 items). `F` is the round's puzzle signature after the script has rolled it
up. Sizes: a pool signature is 9 bytes, a commitment 20, the round's size constant 55 in the
production script and 59 in the test twin. No push of either script is 55 or 59 bytes long.

### Round 1 (paired, runs first)

Stack when the loop starts: `[W] [C0: 92] [F] [pool: 204] [0]`, with nine keys on top of `W`
and the indexes and preimages below them.

1. **Index and preimage fetches return items of `W`.** They aim nine items into `W`. The only
   thing that changes the number of items above `W` during the loop is a selection that takes
   its item from `W`, one more each time. Before the last iteration that is at most eight, so a
   fetch lands at least one item into `W`, never on a script item. So the hashed item `P` is
   always the spender's, never a script constant. Which item of `W` a fetch returns does not
   matter: all of them are arbitrary.
2. **What a selection takes.** Call the copied item `X` and the taken item `Y`. `X` must equal a
   HASH160 output. `Y` is the item directly beneath `X` (both in `W` if `X` is in `W`). So if `Y`
   is in the pool or above it, `X` is too.
3. **The canary.** Let `m` count the selections whose `Y` came from `F` or beneath it: from
   `C0`, from `W`, or `F` itself. Each adds one item above the place of `F`, and nothing in the
   loop removes one (step 1; the selection only moves an item to the top; `PICK` copies).
   `<205> ROLL` therefore returns `F` only if `m = 0`. If `m >= 1` it returns the `m`-th item
   from the bottom of what is left of the pool. At least 195 pool items are left and `m <= 9`,
   so that is a script constant of 9 or 20 bytes, and `SIZE <55 or 59> EQUALVERIFY` compares
   two script-determined values that differ. The spender has nothing to set.
   This covers every case of the misaligned pattern: `X` an unlocking item set to any hash; `X`
   one of round 0's commitments, which the spender can open; `X = F` set to a hash, with `Y` the
   top of `C0`; and the last slot, `X` the deepest commitment after its signature has gone, with
   `Y = F`.
4. **So every `Y` and every `X` lies in the pool, the dummy or the items already taken.** `X` is
   20 bytes, so it is a commitment of this pool, in place or already taken. The multisig takes
   `F` and the nine items under it as signatures and the next as its dummy. Above the pool there
   are the dummy and one item per selection that took something new from the pool. If fewer than
   nine did, the script's empty dummy is among the nine and an empty signature fails a 10-of-10
   multisig. So nine distinct items came from the pool, they are the nine under `F`, and each
   must be a strictly encoded signature: the pool signatures, since a commitment is not one.
   Hence no commitment was ever moved, and each signature `s_j` was taken while directly beneath
   its own `c_j`, with `HASH160(P) = c_j` for an unlocking item `P`.
5. **The puzzle signature** is `F`, an unlocking item, size-checked against the constant in
   place and opposite the puzzle key in the multisig. After the round the stack is exactly
   `[W'] [C0: 92] [L: 195]`, where `L` is 102 commitments and 93 signatures and `W'` has lost
   exactly the items an honest spend consumes.

### Round 0 (two tables, runs last)

Stack when the loop starts: `[W] [C0: 92] [L: 195] [F] [pool: 92] [0]`. In iteration `i` (from
0) the script takes an index `x`, rolls out `X`, the item `x + 288 - i` below the index, hashes
a fetched item `P`, requires `X = HASH160(P)`, and rolls out `Y`, the item `x` below. `X` is
removed, not copied. This is the loop of the unsound unclamped `late` variant, so it is the
part to read slowly. Call `R` everything above `L`: `F`, the pool, the dummy, the items taken.

1. **`R` only grows.** `X` lies at least 280 items below the index (a negative `x` fails at
   the final `ROLL`), and `R` never has more than 103 items. Index and preimage fetches aim more than 380 items down. So nothing but a
   selection's final `ROLL` touches `R`, and that moves an item to the top of `R`: from inside
   `R` (the count stays 94) or from beneath it (one more).
2. **The canary.** `<93> ROLL` returns `F` only if the count is still 94 and `F` was not taken.
   Otherwise it returns one of the lowest pool signatures (83 remain at least, and at most nine
   items were added), 9 bytes against a constant of 55 or 59, and the script fails as in round 1.
   So in an accepted spend every `Y` came from the pool, the dummy or the items already taken:
   `x <= 92`. In particular no `Y` is one of round 1's 93 leftover signatures in `L` (the
   selection that made the unclamped `late` variant unsound) and none is an unlocking item.
3. **Then `X` is never an unlocking item and `P` is never a script constant.** With `x <= 92`,
   `X` is at most `380 - i` below the index. The items above `W` number `381 - i` as long as
   every earlier `X` came from above `W` (each iteration removes exactly one such item), so by
   induction `X` is always above `W`: in `C0` or `L`. Then the items above `W` are exactly as
   many as the fetch depths assume, and every index and preimage fetch returns the item of `W`
   an honest spend would use. The pattern of the known attack needs the commitment fetch to land
   in the unlocking script, and that requires an index that points beneath the pool, which the
   canary refuses.
4. **Ranks.** Let an iteration take a new pool signature, of rank `rho` among those left. With
   `a` signatures taken, `b` commitments of `C0` removed and `l` earlier `X` taken from `L`
   (`b + l = i`), the arithmetic gives `X` as the item of rank `rho + a - b` in what is left of
   `C0`. An iteration whose `Y` is the dummy or an item already taken has its `X` among the
   deepest items of `L` instead (one of round 1's commitments, which the spender can open) and
   takes nothing new. Such a wasted iteration changes neither `a` nor `b`. So `a = b`
   throughout, every other iteration has `X` of rank `rho` in `C0`, and since pool and table
   have lost the same elements, `X` is the commitment of the very element whose signature is
   taken.
5. **Nine of nine.** A wasted iteration leaves fewer than nine signatures above the dummy, and
   the multisig fails on the empty dummy as in round 1. So all nine iterations took a distinct
   pool signature, each with its own commitment equal to the hash of an unlocking item, and `F`
   is an unlocking item, size-checked, opposite the puzzle key.

### What both rounds share, and what the argument depends on

Pinning and the `SIGHASH_SINGLE` check are the code `paper.py` and `late.py` emit. Every
selection of `C(n, t)` is reachable. The evaluator checks that the pools are distinct, disjoint
and inside each multisig's scriptCode and that no other signature-shaped push exists.

Dependencies: 9-byte pool signatures and 20-byte commitments that are not strictly encoded
signatures; size constants (55, 59) that no script push has as its length; no conditional
execution, so both size checks always run; nine keys above the indexes in the unlocking script
(round 1, step 1, needs at least `t`); at least 195 pool items left under round 1's canary
fetch and 83 under round 0's (the builder requires `n >= 2t`); 195 items between round 0's
table and its pool (round 0, step 1; the builder refuses a split round with fewer than `t`,
which is weaker than what step 1 uses, so another configuration needs the step redone). The
argument is for this configuration: two rounds, round 0 split. It was not made for three
rounds, for a split round that is not the last to run, or for two split rounds.

### Searches, none of which is a proof

- **The evaluator's audit**, public lanes, full stage: 53,814 altered spends, 8,297 accepted,
  all with the structure. Core replay of 20 vectors agrees.
- **Concrete altered spends through `bh.interp.verify` in oracle mode**, judged by the
  evaluator's `structure()` with every commitment openable, as the audit does. Written for this
  re-read and not part of this pull request. In oracle mode an equality with an unlocking item
  on either side passes, so "an item set to the hash of a constant" needs no special case; a
  size check does not pass that way, so the planted items include signatures of exactly the
  puzzle's size, which the audit's 9-byte plants are not.
  On the test twin, 4,282,218 spends:
  - every one of the 18 indexes at every depth from -2 to past the bottom of the stack, over
    nothing and over four pads planted under the unlocking script (586 nine-byte signatures,
    143 puzzle-sized ones, and the two alternations of both): 59,202 spends, 6,760 accepted;
  - the same sweep of every index combined with one inserted item (a nine-byte signature, a
    puzzle-sized one, a 20-byte string, a small number, or an empty item) at each of the 61
    positions of the unlocking script: 2,366,190 spends, 13,520 accepted;
  - the same sweep combined with one deleted item at each position: 457,722 spends, 1,352
    accepted;
  - every pair of depths for six pairs of indexes (the last two slots and the first and last
    slot of each round, and the last slot of round 1 with the first and with the last of
    round 0): 1,099,104 spends, 42,974 accepted;
  - 300,000 random spends with one to four indexes moved and up to three items replaced,
    inserted or deleted: 5,026 accepted.

  On the production script, with plants of its puzzle size (55 bytes), the sweeps without the
  insertions: 1,916,802 spends, 56,112 accepted. Every accepted spend of both runs had the
  structure. The accepted ones are other selections of pool elements, and spends in which a
  fetch of a preimage or key lands on another unlocking item that serves as well.
- **A control.** The same harness finds the known unsound case at once: on the evaluator's test
  specimen with its clamp removed, the single-index sweep reports a selection that is not a pool
  element within its first 200 spends. A copy of this builder with the canary removed (puzzle
  signature left on the unlocking script) is *not* found unsound by the single-index sweep:
  in this layout an index beneath round 0's pool also drags the commitment fetch into the
  unlocking script, which misaligns the puzzle fetch by itself. I did not search that copy
  further and do not claim anything about it.

I found no accepted spend without the structure and no case the steps above do not cover. A
maintainer should read round 0, steps 1 to 4, before this instance is relied on.

## Model slack

- **The level is the pinning cap**, 80.011, as for every recorded `standard` instance. Before
  the cap the model's own search (`bh.model._level`) prices these rounds at 81.196 bits. For
  comparison: `paper-two-round` 81.521, `late-unclamped-124-107` 81.126, 92-choose-9 twice
  81.505. A contract without the cap would rank this instance by 81.196.
- **Round 1 is plentiful and round 0 scarce**: 2.07 and 0.79 expected solutions per pinned
  transaction. That shape is priced by BH-SEC-2's partial-search attacker; the 81.196 above is
  after it.
- **Two rounds, 5-byte pinning, two round signatures**: assumptions A2 and A3 are used exactly
  as the baseline uses them, and the open question about hash-type byte freedom per round beyond
  the first applies to this instance as it does to the baseline, not more.

## Architecture

Declared `paired-table`, by the maintainer's decision; the first search proposed a separate
architecture for this design. On the registry's axis (how a selection is made, bound to its
commitment and tied to the puzzle signature) round 1 is a paired table exactly: one table of
adjacent pairs, one index used by `PICK` and `ROLL`, binding by adjacency. What differs from the
registry entry, stated so that a reader can disagree:

- **Confinement.** The entry describes a size constant under the table read by `PICK`. Here the
  puzzle signature lies under the pool and is read by `ROLL`. Both are one height check per
  round in place of a clamp per selection; which item plays the canary is the difference.
- **Round 0 is not paired.** With `BINO_SPLIT=0`, nine of this instance's eighteen selections
  are made in the two-table form: an index used through `ROLL` once per table with `<k> ADD`
  between, which is how the entry describes `rolled-subset`, minus the clamp. Only the canary
  is shared with round 1. The instance is a paired table in the round that carries the cheaper
  selection and a two-table round where the grind is cheaper for it. If the registry is read
  strictly ("one table of adjacent pairs per round"), this is a hybrid and the maintainer may
  prefer to file it differently.

## Experiments

Counts from the current evaluator. The first row is the ledger's, the row marked "this" is the
full-stage run, the others are counted with `Judge.count` without lanes. "Rounds alone" is the
level before the cap.

| | Bytes | Opcodes | Work | Rounds alone | Compressions per attempt (round 0, 1) | Score |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| `paired-3round-pin5` (recorded) | 10,741 | 201 | 2^43.505 | 82.019 | | 24,510,429 |
| `pairs`, 105:9, 74:10 | 7,531 | 195 | 2^46.222 | 81.150 | 50, 9 | 109,621,538 |
| `canary`, both paired, 74:10, 92:9 | 7,128 | 195 | 2^46.463 | | 10, 50 | 122,619,394 |
| `canary`, both paired, 92:9, 102:9 | 7,925 | 186 | 2^46.410 | 81.196 | 10, 59 | 125,347,157 |
| `canary`, round 0 split, 92:9, 92:9 (the first search's point) | 7,644 | 196 | 2^45.955 | 81.505 | 8, 29 | 92,941,649 |
| `canary`, round 0 split, 102:9, 92:9 | 7,954 | 196 | 2^45.906 | 81.196 | 9, 31 | 93,481,315 |
| `canary`, round 0 split, 104:8, 102:9 | 8,252 | 186 | 2^46.067 | | 9, 32 | 102,901,368 |
| this: `canary`, round 0 split, 92:9, 102:9 | 7,954 | 196 | 2^45.746 | 81.196 | 8, 29 | 83,668,120 |

Engine line of the full run:
`reference-48+core-20: 48 lanes, 53814 altered spends (8297 accepted, all sound)`.

The point was found by a hill-climb with real builds from 92:9, 92:9 (one step in `n` or `t` of
a round). The gain is in retries: ten more elements in the round that is cheap in bytes per
solution raise its solutions per transaction from 0.79 to 2.07, the chance that both rounds
have one from 0.30 to 0.48, and the transactions tried per spend fall from 3.37 to 2.10, for
310 bytes. The four neighbours one element away all score worse, between 85.1 and 85.9
million: each costs one compression per attempt in both rounds (9 and 30 instead of 8 and 29),
which is what crossing a 64-byte block boundary of the hashed scriptCode costs. So the optimum
is partly an accident of alignment, and nobody has tuned alignment on purpose.

What did not work:

- **Both rounds paired.** 10 operations fewer and about the same bytes, but 59 compressions per
  attempt in the round behind the paired pool: score 125 million.
- **The larger pool in round 0** (102:9, 92:9): the same bytes and 12 percent more work. The
  scarce round is then the one whose attempts cost 31 compressions.
- **A tenth selection in either round**: 205 or 206 operations.
- **Eight selections in round 0** (104:8): ten operations fewer, but 0.23 solutions per
  transaction and 5.5 transactions per spend.
- **Splitting the round that runs first**: the builder refuses it. Nothing would lie between
  its table and its pool, and round 0's step 1 needs that distance.
- **A preimage whose length is the index** (`SIZE` in place of an index fetch): eight
  operations in the loop however the stack is arranged, against seven. From the first search,
  not measured again.
- **The element's public key as its preimage**: 17 unlocking bytes less per element, but the key
  is recoverable from the 9-byte signature in the script, so anyone could open any commitment.
  Not built; the evaluator's binding check refuses a preimage equal to a public key.

## Result and next steps

7,954 bytes, 196 operations, 2^45.746 compressions, 80.011 bits (rounds alone 81.196), score
83,668,120 on public lanes. Against the recorded `standard` rows:

| | Bytes | Opcodes | Work | Score |
| --- | ---: | ---: | ---: | ---: |
| `paper-two-round` (baseline) | 9,349 | 199 | 2^46.740 | 198,865,940 |
| `late-pools` | 9,293 | 199 | 2^46.081 | 125,190,801 |
| `late-unclamped` | 9,269 | 191 | 2^46.121 | 123,217,063 |
| `late-unclamped-124-107` | 9,067 | 201 | 2^45.743 | 97,605,646 |
| `early-openings-79-109` | 7,851 | 197 | 2^45.189 | 56,420,360 |
| `paired-3round-pin5` | 10,741 | 201 | 2^43.505 | 24,510,429 |
| this | 7,954 | 196 | 2^45.746 | 83,668,120 |

Standing, plainly: it is 3.4 times the score of its architecture's best, so it does not qualify
as that. `python3 challenge.py decide` on a local row answers `front`: no recorded instance has
at most 7,954 bytes and at most 196 operations, so the third acceptance rule holds with nothing
to compare against. The nearest row is `early-openings-79-109` (`rolled-subset`), recorded while
this was being prepared: 103 bytes smaller, 0.56 bits less work, score 56,420,360, with one
operation more. It is better than this instance in everything but that operation, and it is the
only reason the comparison is empty and not lost. Against the other two-round rows this
instance has 14 percent less score than `late-unclamped-124-107`, with 1,113 fewer bytes and 5
fewer operations at the same work to within 0.003 bits. Whether one operation is enough reason
for a row is the maintainer's call; the case for it is the two-round paired-table instance
itself, not its place on the front.

Caveats, in order of weight: the soundness argument has been read only by its authors; round 0
is a two-table round filed under `paired-table`; the rounds have 1.2 bits above the floor that
the cap hides.

Next: the work is still that of 40-bit puzzles. `score.json` attributes 2^43.94 of the 2^45.75
to pinning with its retries, 29 percent; the rest is the two round searches at 8 and 29
compressions per attempt, so the 29 of round 1 is the largest cost left for a two-round design.
Five operations are free; they do not buy a selection (nine or ten each). Tuning the pools' positions modulo 64 bytes on purpose
is untried. The canary could be tried in place of the markers of the three-round design, where
it costs the same number of operations; that needs the argument made again for three rounds.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. The design
and the builder come from the first search under BH-SEC-1, where an agent built it independently
of `pairs`; this submission ports it under the name `canary`, re-tunes it under BH-SEC-2 and
re-reads its soundness argument against the corrected audit. Builds on the notes of
`paired-3round-pin5` (the paired selection and the shape of its argument), `late-pools`
(commitments ahead of the pools) and `late-unclamped` (where a clamp is needed).
