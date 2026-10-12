# Late pools, first round unclamped, 124-choose-8 and 107-choose-9

The layout of `late-unclamped` with different pool sizes and a ninth selection in the unclamped
round: 202 fewer bytes and 0.38 bits less work, at the full 201 operations.

## Goal and starting point

`standard/late-unclamped` (two rounds of 120-choose-8, 9,269 bytes, 191 operations, 2^46.121
compressions, score 123,217,063). Its notes end with eight operations left unused. Under
BH-SEC-2 every design with 5-byte pinning whose rounds are worth at least 80.0 bits is counted
at the pinning cap, 80.011 bits (SECURITY-MODEL.md, section 4). The pool sizes of that instance
are the paper's and were never tuned for cost. The goal was to find the pool sizes and selection
counts that score lowest in this layout while the rounds stay above the floor on their own.

## Mechanism

No builder change. `builders/late.py` with `BINO_CLAMP=later`, as in the parent, and
`BINO_ROUNDS=124:8,107:9`: round 0 has a pool of 124 and selects 8, round 1 has a pool of 107
and selects 9. Round 1 is the round that runs first and the one without the index clamp.

What moves:

- **Opcodes, 191 to 201.** Counted from the builder: a clamped selection costs 11 operations
  (9 in the loop, one to roll its key up, one for the key in the multisig) and an unclamped one
  10. A round costs 5 more. Pinning costs 13. The parent is 13 + (11 x 8 + 5) + (10 x 8 + 5) =
  191. This instance is 13 + (11 x 8 + 5) + (10 x 9 + 5) = 201. The ninth selection costs 10
  operations: the 8 the missing clamp freed in the parent and the 2 the paper's script had
  spare. Nothing is left for an application.
- **Bytes, 9,269 to 9,067.** The tables hold 231 elements against 240. Each element is 31 bytes
  in the locking script (a 21-byte commitment push and a 10-byte signature push), so nine fewer
  elements save 279 bytes. The ninth selection gives part of that back: one more loop iteration
  in the script, and one more key, preimage and index in the unlocking script.
- **Work, 2^46.121 to 2^45.743.** A round with more selections has a solution more often, so
  fewer transactions are tried per spend, and each transaction tried costs a 2^40 pinning
  puzzle. Round 0 has 0.997 expected solutions per transaction (0.761 in the parent) and
  round 1 has 3.248 (0.761). The evaluator reports 1.648 transactions tried per spend. The
  same calculation for two rounds of 120-choose-8 gives 3.52. Compressions per attempt are 10
  for round 0 and 31 for round 1.

## Soundness

The mechanism that needs an argument is the missing clamp, and the argument is the parent's.
It is restated here briefly; `late-unclamped/NOTES.md` has the full version.

Round 1 runs first and does not clamp its indexes. The clamp exists so that an index cannot
reach a signature outside its own pool. In the late layout nothing selectable lies below the
pool of the first round to run:

1. Directly below round 1's signatures are the commitment tables. A commitment is 20 bytes of
   hash output, not a strictly encoded signature, and the evaluator refuses an instance with a
   signature-shaped push outside its pools. An index landing there fails the multisig on
   encoding.
2. Below the tables is the unlocking script. An index landing there can fetch a signature and
   a matching commitment of the spender's choosing, and that iteration passes. It removed two
   items from the witness and none from the tables, so every later constant depth is two items
   too shallow. A remaining iteration then fetches a commitment as its index. With no iteration
   remaining, the key fetches end by taking the two deepest commitments of round 0's table as
   multisig keys, and those are not public keys.
3. No iteration can undo the offset, because an out-of-range iteration never shortens a table.

Round 0 runs second, with the signatures round 1 did not select lying directly below its pool.
It keeps its clamp in this instance, exactly as in the parent.

What is different from the parent, and why the argument still applies: the unclamped round
has nine iterations and not eight, and the pools have 124 and 107 elements. The argument uses
only what lies below the first pool to run and that two non-key constants sit directly above
the witness. Neither depends on the pool sizes or on the number of iterations, and the builder
derives every depth from `n` and `t`. The argument does depend on this layout; a variant that
moves the tables or the witness could lose it.

The audit under BH-SEC-2 sweeps every index over every depth, with and without signatures
planted under the witness, by a spender who can open any commitment and who may also set an
unlocking item to the hash of a script constant. That last ability is what refuses the variant
with no clamp in any round: there the accepted spend takes a signature the previous round had
not selected, which needs an unclamped round that runs after another. Here the only unclamped
round runs first. In the local run every accepted alteration kept the declared structure
(58,395 altered spends, 32,350 accepted, all sound). That is a search and the argument above
is prose. Like the parent, this instance needs a maintainer's reading before it is relied on.

The security level. `security_bits` is 80.011, the pinning cap, as for the parent. The cap
hides what the rounds are worth, so it is stated here: computed with the evaluator's own
`bh.model._level` at the pinning cost, the rounds alone are worth 81.126 bits, against 81.521
for two rounds of 120-choose-8. The floor is 80.0. This instance therefore spends 0.39 bits of
the 1.52 bits of slack the parent had above the floor, and keeps 1.13. The loss comes from
round 1, which has more selections (2^41.705) than its 40-bit puzzle needs: the model's
attacker searches part of such a round. The pools are distinct signatures in disjoint pools,
which the evaluator checks, so the selection counts are the declared ones.

Hash-type byte freedom is outside the model (SECURITY-MODEL.md, section 6). This instance has
two rounds and one spender signature per round, as the parent has, so it does not change how
much that matters.

## Architecture

Unchanged: `rolled-subset`. Separate signature and commitment tables, one index walked through
`OP_ROLL` once per table, one pool, one table and one multisig per round. Only pool sizes and
one selection count differ from the parent, which is a refinement.

## Experiments

A hill-climb over pool sizes and selection counts, starting from `120:8,120:8`. Every
candidate was built and measured, and a move was accepted only if the built instance scored
lower. Candidates over 201 operations or with rounds worth less than the floor were not
considered.

| | Rounds | Bytes | Opcodes | Work | Security | Rounds alone | Score |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `late-unclamped` (parent) | 120:8, 120:8 | 9,269 | 191 | 2^46.121 | 80.011 | 81.521 | 123,217,063 |
| clamped layout, same search | 120:8, 131:8 | 9,655 | 199 | 2^45.825 | 80.011 | 81.260 | about 109.0 million |
| this | 124:8, 107:9 | 9,067 | 201 | 2^45.743 | 80.011 | 81.126 | 97,605,646 |

The parent's row is the recorded one. The last row is the local full-stage run of this
instance:

```
python3 challenge.py run binohash challenges/binohash/submissions/standard/late-unclamped-124-107 -- --core tools/core/target/release/cchk
OK  reference-48+core-20: 48 lanes, 58395 altered spends (32350 accepted, all sound)
    bytes 9067 (locking 7826 + unlocking 1241)  opcodes 201  work 2^45.743 compressions  security 80.011 bits (floor 80.0)
challenge score (bytes x opcodes x work): 97605645.570 = 9067 x 201 x 2^(45.743 - 40)
```

**Negative: the clamped layout.** The same hill-climb with `BINO_CLAMP=all` ended at
`120:8,131:8`. With every round clamped a ninth selection costs 11 operations and does not fit
in 201, so the only way to cut retries is a larger pool, which costs 31 bytes per element. It
reaches less work than the parent but is 386 bytes larger, and its score of about 109.0
million is 12% above this instance. It is not submitted. The middle row was measured during
the search and was not run again for these notes.

**What limits the result.** The opcode count: the instance uses all 201. A tenth selection
does not fit in either round.

The baseline `paper-two-round` scores 198,865,940.

## Result and next steps

9,067 bytes, 201 operations, 2^45.743 compressions, 80.011 bits against a floor of 80.0, on 48
local lanes with the Bitcoin Core replay (engine `reference-48+core-20`). Score 97,605,646, which is 21% below
the parent and 51% below the baseline. Local numbers are claims; the judge's run is the result.

Caveats:

- The hill-climb accepts single moves and can stop at a local minimum. It was not an
  exhaustive search of the pool sizes.
- The soundness of the missing clamp rests on the parent's argument and on an audit that is a
  search.
- The rounds alone are worth 81.126 bits. A later change to the model that lowered the value of
  an oversized round by more than 1.1 bits would put this instance below the floor while the
  parent stayed above it.

Next:

- Compressions per attempt depend on where a pool falls modulo 64 bytes. Round 1's attempts
  cost 31 compressions, most of them rehashing round 0's pool and loop. The search here scored
  whole builds and so saw this effect, but nothing was done to move a block boundary on
  purpose.
- Unclamping round 0 as well would free eight more operations, nearly a tenth selection. It
  needs a layout in which round 1 leaves nothing selectable behind, and an argument for it.
- An operation saved per selected element would now pay in both bytes and work, since the
  opcode budget is the binding count.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer. It builds
on `standard/late-unclamped` and, through it, on `standard/late-pools`. No builder code was
changed.
