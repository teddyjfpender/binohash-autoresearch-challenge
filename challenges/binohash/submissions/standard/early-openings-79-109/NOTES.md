# Early openings, 79-choose-10 and 109-choose-9

The commitments are opened before any signature pool is pushed, so a round's grinding attempt
no longer rehashes its selection loop. The same split makes a selection cost nine operations
instead of eleven, and no index is clamped. 7,851 bytes, 197 operations, 2^45.189 compressions
at 80.011 bits. The soundness section is the part to read: there is no clamp, and an unclamped
copy of the late layout is one of the evaluator's refused defects.

## Goal and starting point

`standard/late-unclamped` (instance `66a917ff...`): 9,269 bytes, 191 operations, 2^46.121
compressions, 80.011 bits, score 123,217,063. Its work is three pinning puzzles once, then 3.52
pinned transactions per spend, each with a `SIGHASH_ALL` puzzle at 3 compressions per attempt
and rounds at 10 and 32 compressions per attempt.

The best recorded instance of the architecture is its descendant `late-unclamped-124-107`
(9,067 bytes, 201 operations, 2^45.743, score 97,605,646), which keeps the late layout, chooses
the pools under BH-SEC-2 and spends every operation on a seventeenth selection. This submission
changes the layout instead, and is compared with both.

Two things were to change: what has to sit behind a pool in the script (the 10 and the 32), and
the operations a selected element costs (which decide how many selections fit under 201, and so
how small the pools can be).

The layout and the builder are an earlier agent's work under the previous security model,
BH-SEC-1. That model credited an oversized round with security it does not give, and the
standard floor was then 81.5 bits. Two instances of this layout were tuned to that floor
(76-choose-10 with 125-choose-9, and 93-choose-9 with 99-choose-10) and were priced at 81.50
bits. BH-SEC-2 lets the attacker search part of a round, and under it their rounds are worth
81.04 bits, below the old floor. Neither is on this board. This submission keeps the layout
and chooses the pools again under BH-SEC-2.

## Mechanism

`builders/early.py`. A round's grinding attempt rehashes the sighash preimage from its
innermost selected signature to the end of the script, so everything behind a pool is paid for
on every attempt. In the paper's loop and in the late layout that includes the whole selection
loop. Only one step of the loop needs the pool: rolling the signature out. So a round is split
in two phases.

- *Phase 1*, before any pool is pushed. The round's commitment table is pushed and, for each
  slot, `OP_1 <d> OP_PICK OP_ROLL <d'> OP_ROLL OP_HASH160 OP_EQUALVERIFY`: the index is copied
  out of the unlocking script (it stays there), the commitment at that depth is rolled out and
  compared with the hash of the revealed preimage.
- *Phase 2*, after the round's pool is pushed. For each slot `<d> OP_ROLL OP_ROLL`: the same
  index is rolled up and the signature at that depth is rolled out. Then the multisig is
  assembled as in the paper.

Script order: pinning; the size check of round 0's puzzle signature; table and phase 1 of round
0; table and phase 1 of round 1; the two puzzle keys; round 1's pool, phase 2 and multisig;
round 0's pool, phase 2 and multisig. Round 0 is the back round: its pool is last and has only
its own phase 2 and multisig behind it.

**Nine operations per selection.** In phase 2, slot `i` finds the multisig dummy and `i`
selected signatures above the pool, so the index is the element's rank plus `i + 1`. Phase 1
pushes one constant (`OP_1`, not a counted operation) per slot above the commitment table, so
the same number is the commitment's depth and no `OP_ADD` is needed. A selection costs `PICK
ROLL ROLL HASH160 EQUALVERIFY`, `ROLL ROLL`, the roll of its key and the key in the multisig:
nine, against eleven in the paper's loop and ten without its clamp. The script is 23 + 9 per
selection, plus one per rolled puzzle key and per separator: 23 + 9 x 19 + 3 = 197. Nineteen
selections fit where the late layout fits seventeen, and that is where the bytes go: 188 pool
elements at 31 bytes each instead of 240.

**What is behind a pool.** Round 0's puzzle signature is the top of the unlocking script once
pinning has consumed its four signatures, and its size is checked there, so that check is
behind no pool. With `BINO_KEY_ROLL=0,1` both puzzle keys are pushed ahead of both pools and
rolled into their multisigs: one operation each, and about 30 bytes fewer behind the pools for
each (a 34-byte push becomes a roll). Round 0's attempts cost 6 compressions and round 1's 20.
Round 1 still rehashes round 0's whole pool; that is inherent to two pools in one script and is
the largest remaining term.

**Pinning order.** `BINO_PIN_ORDER=1,2,4,3` with `BINO_PIN_SEP=3` checks the payload puzzle
last, behind an `OP_CODESEPARATOR`. That puzzle then signs a shorter scriptCode than the other
three, which lets the three puzzles that are solved once per spend cost 2 compressions each
(2, 3, 3 without it). The `SIGHASH_ALL` puzzle costs 3 either way.

**The pools.** With 5-byte pinning the level is the pinning cap, 80.011 bits, for every design
whose rounds are worth at least that. These rounds are worth 81.107 bits without the cap (the
model's formula, section 4 of SECURITY-MODEL.md, evaluated for 79-choose-10 and 109-choose-9
under 40.006-bit puzzles); `late-unclamped`'s are worth 81.521 and `late-unclamped-124-107`'s
81.126. Above the cap the pools trade
bytes against retries. A round has a solution for a pinned transaction with probability
`1 - exp(-S / 2^W)`; here the rounds have 1.31 and 3.86 solutions on average, both have one
with probability 0.714, and a spend tries 1.40 transactions. The old instances had 0.86 and
13.9 solutions: the second pool was far larger than retries justify and the first too small,
which is what tuning to the old model's 81.5 produced.

## Soundness

Unchanged parts first. Pinning is the paper's five checks. The order of the four puzzle checks
and one `OP_CODESEPARATOR` change which script bytes a signature commits to, not which
transaction fields: the puzzles keep their numbers, their keys and their sighash modes, their
targets stay pairwise disjoint, and the hardcoded `SIGHASH_SINGLE` check is the first thing in
the script as before. The round signatures sign the scriptCode from the separator on, which
holds both pools; the evaluator checks that every pool element lies inside it. Each multisig is
`t+1` of `t+1` with the puzzle key last and a size-checked spender signature opposite it. The
number of rounds and of spender signatures is the baseline's, so hash-type byte freedom
matters as much as it does there. Commitments are HASH160 of 16-byte preimages, one per
element, in tables separate from the pools.

What changed is the selection, and **no index is clamped**. The audit refuses a copy of the
late layout with no clamp: there the last index of the round that runs second reaches the first
round's unselected signatures, the commitment fetch for it lands on an unlocking item, the
preimage fetch on a script constant, and the spender sets the one to the hash of the other
(SECURITY-MODEL.md section 8, DESIGN.md section 5). The argument below is written against that
pattern: an index that leaves its table, so that later fetches at constant depths land
somewhere else, with a spender who can make any equality hold in which one side is an unlocking
item itself.

**Notation.** `W` is the unlocking script as pinning leaves it, top first: round 0's puzzle
signature at position 0, then round 0's indexes and preimages, round 1's indexes and
preimages, round 1's puzzle signature, round 1's keys, round 0's keys. `C0`, `C1` are the
commitment tables and `P0`, `P1` the pools. Everything the script pushes lies above `W`. From
the bottom up: what is left of `C0`, the ten constants of round 0's phase 1, `C1`, nine
constants, the two puzzle keys, `P1`, and later `P0`.

Every operation has a fixed stack effect and the script has no branches, so the stack size at
every step is the honest one plus whatever the spender put under `W`. Every fetch has a
constant depth except two per slot: the commitment in phase 1 and the signature in phase 2,
whose depth is the index. Call these the *variable* fetches. The constant fetches aimed at `W`
are: per slot of phase 1, the copy of the index and the roll of the preimage; per slot of phase
2, the roll of the index; then the puzzle signature and the keys. An honest spend consumes `W`
entirely, and the fetch of round 0's puzzle signature comes after every variable fetch.

**A. A variable fetch that takes an item of `W` ends in a failed script.** Call such a fetch a
*fake*. Let `d` be the number of items above `W` minus the number an honest spend has there at
the same step. A constant fetch that the honest spend aims at position `p` of `W` lands at
position `p - d`, or, if `p < d`, on one of the lowest script-pushed items (a *miss*).

- `d` starts at 0. A variable fetch moves an item to the top: from above `W` it leaves `d`
  unchanged, from `W` (a fake) it adds one.
- A constant roll aimed at `W` adds one item above `W` in the honest count; when it lands in
  `W` it leaves `d` unchanged, and a miss subtracts one. A copy never changes `d`.
- The two rolls of the puzzle keys are aimed above `W` and could reach `W` only with `d < 0`,
  which never happens.

Position 0 of `W` is round 0's puzzle signature from the end of pinning until the last
multisig, and its fetch comes after every variable fetch. Every constant fetch before that one
has `p >= 1`: the copies of round 0's indexes are at 1 to 10, round 0's index rolls in phase 2
at 1, and the others at 11 or deeper. A miss needs `p < d`, so it needs `d >= 2` and leaves
`d >= 1`. Hence after one fake `d` never returns to 0, and when round 0's puzzle signature is
fetched (`p = 0`) that fetch takes the item `d - 1` places above `W`. That item is a commitment of `C0`: the lowest script-pushed items are `C0`'s
79 commitments, each of the 38 variable fetches removes at most one of them if it is not a
fake, each miss removes one and lowers `d`, so at least `41 + d` remain. A 20-byte commitment
then stands where the signature under round 0's puzzle key is checked. It is not empty and not
a strictly encoded signature, so the last multisig fails; encoding rules apply in the audit's
oracle mode as they do in consensus. The builder refuses pool sizes for which the count above
could run out (round 0's pool must hold three times the selections of both rounds).

This is the step that answers the misaligned-fetch pattern. In oracle mode a fake in phase 1
passes its own equality, because the commitment side is then an unlocking item. It does not
matter: no later choice of the spender's undoes the offset before the last multisig.

**B. With no fake, every constant fetch reads the honest position of `W`.** Then `d = 0`
throughout, no miss is possible, and `W` is consumed item by item in the honest roles. In
particular phase 1 and phase 2 read the same item as the index of a slot, so the same number,
whatever it is; each preimage is an unlocking item; each puzzle signature is the item whose
size was checked.

**C. Round 0, with no fake.** In phase 1 of slot `i` the stack above `W` is `i + 1` constants
over the `79 - i` commitments left in `C0`, and nothing else: `C0` is the first thing pushed
after pinning. An index of `i` or less takes a constant (the byte `01`), which no 20-byte hash
equals and which is not an unlocking item, so the comparison fails in oracle mode too. An index
above 79 reaches `W`, a fake. So every index of round 0 is in `[i + 1, 79]` and takes a
commitment of `C0`, which the hash of that slot's preimage must equal. In phase 2 of slot `i`
the stack is `i` selected signatures and the dummy over the `79 - i` signatures left in `P0`,
in the table's order. The same number takes the signature of the same element, and removes it,
so no element is taken twice. This is where the clamp would be needed: `P1`'s unselected
signatures lie directly below `P0`, and an index above 79 would take one. Phase 1 has already
confined the index, including the last slot's (`i = 9`: 10 constants over 70 commitments, an
index of 80 takes round 0's puzzle signature out of `W`, a fake).

**D. Round 1, with no fake.** In phase 1 of slot `i`, below `C1` lie round 0's ten constants
and the 69 commitments round 0 left unopened. An index of `i` or less, or one of the ten values
that land on round 0's constants, fails as in C, and one that reaches `W` is a fake. Any other
index above 109 takes one of round 0's commitments, and the spender, who knows every preimage,
can open it. Take the first slot `j` that does so. Its index is at least 120, and until then both of round 1's tables have lost the
same elements. In phase 2 the same number reaches at least eleven places below `P1`, where
there are the two puzzle keys, nine constants, `C1`, ten constants and `C0`: no signature. The
item taken is either a script constant that is not a strictly encoded signature, and round 1's
multisig fails on encoding, or an item of `W`, a fake. So every index of round 1 takes a
commitment of `C1` in phase 1 and, by the same count as in C, the signature of the same element
of `P1` in phase 2. For the last slot (`i = 8`) the reach below `P1` is at least eleven places
as for any other.

**E. The rest.** With all 19 variable fetches inside their pools, the number of items above
each puzzle key is the honest one, so each key roll takes its key, and each multisig checks its
`t` selected signatures and the size-checked puzzle signature against the `t` keys from `W` and
the puzzle key.

So a spend is accepted only if each round takes `t` distinct elements of its own pool, each
with its own commitment compared under `OP_EQUALVERIFY` with the hash of an unlocking item.

**What the argument depends on**, each of which a variant could lose:

- Round 0's table and phase 1 come first, so that below `C0` there is only the unlocking
  script. With the two tables exchanged, an index of round 0 opens one of round 1's left-over
  commitments and takes one of round 1's left-over signatures. That variant was built as a
  control (below) and is refused.
- The pool pushed first is the round that takes no clamp for a second reason: nothing
  signature-shaped lies below it. The evaluator refuses any signature-shaped push outside the
  pools, and A and D rely on no commitment or key being a strictly encoded signature.
- The unlocking script is consumed entirely, and the last fetch that matters is aimed at its
  top. Step A is a counting argument on that.
- At most two rounds. With three, a middle round has another pool's left-overs below its own
  and another table's below its table. The builder refuses three.
- `BINO_PAD=0,0`. With padding, zero-byte pushes lie between `C0` and `W` and before `P0`. They
  are not 20 bytes and not signatures, and A to D go through with small changes, but this
  instance does not use them and the changed counts were not checked here.

**Checks run.** The audit on the 48 public lanes: 54,912 altered spends, 10,749 accepted, all
with the declared structure. And a separate search aimed at the argument, in oracle mode
against the test twin with the evaluator's interpreter and its structure check, with 130
planted nine-byte signatures under the unlocking script:

| Alteration | Spends | Accepted | Without the declared structure |
| --- | ---: | ---: | ---: |
| One index set to every value from -2 to 699 | 13,338 | 1,690 | 0 |
| One item inserted at each position of `W` (a planted signature, a signature of the puzzle size, or 20 bytes) and one index set to each of 359 values | 1,227,780 | 103,090 | 0 |
| One item inserted and one deleted, at every pair of positions, with an index aimed at or beside the inserted item in either phase | 247,800 | 0 | 0 |
| The first or last `k` indexes of round 0 sent to depths 78 to 183, past the pool, with 0 to `k + 1` items inserted at one of seven positions | 667,800 | 2,272 | 0 |
| Random: up to four insertions, two deletions and five indexes, the values drawn mostly from the boundaries of the regions above | 640,000 | 2,176 | 0 |
| Total | 2,796,718 | 109,228 | 0 |

In the first row a slot `i` is accepted for exactly the values `i + 1` to `n` of its round, in
all 19 slots, which is the range C and D give. The index values of the second row are every
depth from 0 to 214 and from 296 to 439, which includes the depths at which `W` begins in each
phase (80, 189, 300 and 369). In a sample of that row by position, a spend was accepted only
when the item was inserted at round 1's puzzle signature or below it: among the keys, where it
replaces a key the spender chooses anyway, or as a signature of the puzzle's size in that
signature's place.

As a control, the same builder with the two commitment tables exchanged was built outside the
repository. The fourth row's search finds accepted spends without the declared structure
there at once (the last index of round 0 set to 89 takes one of round 1's left-over
signatures), and the evaluator refuses that control at stage `soundness` on its first lane for
the same alteration.

This is prose and a search, not a proof. Steps A and B are a counting argument that I believe
is complete for this script; C and D enumerate what lies at each depth, and the first row of
the table checks their ranges against the instance. A maintainer's reading is needed before
this instance is relied on.

## Architecture

`rolled-subset`. The registry entry's distinguishing property is: signatures and commitments
are two separate tables on the stack, a selection is an index walked through `OP_ROLL` once per
table, and every round has a pool, a commitment table and a multisig of its own. All three
hold here. What differs is when the two walks happen (the commitment walk before the pools are
pushed, the signature walk after, with the index copied for the first) and that the clamp is
replaced by a layout argument, as it is for one round of `late-unclamped`. No change of the
tables, of the binding or of the multisig is involved, and "the same tables and the same
selection loop in a different order or position in the script" is listed in ARCHITECTURES.md as
a refinement. `early` is a new builder, which the classification rules do not know, so the
declaration is for a maintainer to confirm.

## Experiments

`python3 challenge.py run binohash challenges/binohash/submissions/standard/early-openings-79-109`
with the Core comparison: `reference-48+core-20: 48 lanes, 54912 altered spends (10749
accepted, all sound)`. The first two rows are the ledger's, with the last two columns of the
second taken from that submission's notes. The other rows are local screen-stage runs of the
same evaluator.

| Instance | Bytes | Opcodes | Work | Security | Per attempt | Tries | Score |
| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `late-unclamped`, 120:8,120:8 | 9,269 | 191 | 2^46.121 | 80.011 | 10, 32 | 3.52 | 123,217,063 |
| `late-unclamped-124-107`, 124:8,107:9 | 9,067 | 201 | 2^45.743 | 80.011 | 10, 31 | 1.65 | 97,605,646 |
| `early`, 76:10,125:9, the old knob set | 8,301 | 196 | 2^45.222 | 80.011 | 6, 20 | 1.73 | 60,724,664 |
| `early`, 93:9,99:10, these knobs | 7,977 | 197 | 2^45.297 | 80.011 | 6, 22 | 1.72 | 61,781,963 |
| `early`, 79:10,109:9, no other knob | 7,843 | 194 | 2^45.340 | 80.011 | 6, 22 | 1.40 | 61,628,858 |
| this: 79:10,109:9, key rolls, separator | 7,851 | 197 | 2^45.189 | 80.011 | 6, 20 | 1.40 | 56,420,360 |

"Per attempt" is compressions for round 0 and round 1; "Tries" is pinned transactions per
spend. The old knob set is `BINO_KEY_ROLL=0 BINO_PAD=41,3 BINO_PIN_ORDER=2,1,3,4
BINO_PIN_SEP=1`.

The pools come from a hill-climb over the pool size and selection count of both rounds, with a
real build and count for every candidate, accepting only moves whose built instance scores
lower. It started from 93:9,99:10 with this instance's knobs and stopped at 79:10,109:9. The
same climb from 76:10,125:9 with the old knob set did not move, and that instance stays at
60,724,664. The climb was run before this write-up; the rows above are the endpoints measured
again.

### What did not work

Layout experiments of the earlier agent, which do not depend on the security model and were
not repeated here:

- **Both pools with short tails.** Interleaving the pools needs the round that runs second to
  address signatures whose depths the first round's `OP_ROLL`s shifted by a selection-dependent
  amount. `OP_PICK` in the first round avoids the shift but lets an element be taken twice, and
  ordering the indexes costs four operations per selection.
- **The plentiful round's last elements behind the other pool.** The pool is then two runs on
  the stack with the other pool's left-overs between, and bridging the gap costs three
  operations per selection.
- **Twenty selections.** 23 + 9 x 20 is 203 operations.
- **Exchanging the two commitment tables.** Unsound, see above. This one was rebuilt and
  checked here.

Depended on the old model, and dropped: the earlier search over neighbouring pool sizes was
run at the old floor of 81.5 bits under BH-SEC-1 and its optimum (93 and 99 elements) is not
one under BH-SEC-2. The remark that a block could be taken off the back round's tail was
measured on the 76:10,125:9 instance and has not been measured here.

## Result and next steps

7,851 bytes (locking 6,508, unlocking 1,343), 197 operations, 2^45.189 compressions, 80.011
bits against a floor of 80.0, stack peak 391. Local score 56,420,360: 1.73 times below the
best recorded instance of the architecture (`late-unclamped-124-107`, 97,605,646), 2.18 times
below `late-unclamped` and 3.52 times below the baseline `paper-two-round` (198,865,940). The level is
the pinning cap; the rounds alone are worth 81.107 bits under BH-SEC-2. These are local
numbers on public lanes. The judge's run is the result.

Open leads:

- **Padding was not tuned for these pools.** `BINO_PAD` moves the pools relative to SHA-256's
  64-byte blocks. The earlier agent tuned it for other pool sizes; here it is `0,0` and the
  hill-climb did not vary it. Round 1 at 20 compressions and the `SIGHASH_ALL` puzzle at 3 may
  each be one block from a boundary.
- The hill-climb is local and was run from one start per knob set. A joint search over pools,
  key rolls, padding and separator placement has not been done.
- Four operations are free. A twentieth selection needs nine.
- Round 1 rehashes round 0's pool: most of its 20 compressions.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. The
layout, the builder and the layout experiments are an earlier session's work with the same
model and harness; this submission ports the builder unchanged, chooses the pools under
BH-SEC-2 and re-reads the soundness argument against the corrected audit. Builds on the late
layout and the notes of `late-unclamped`.
