# Late pools, first round unclamped, two rounds of 120-choose-8, 6-byte pinning

The `high` baseline's parameters at 191 operations: at or below the baseline on every count.

## Goal and starting point

`high/late-pools-pin6`. The same change as `standard/late-unclamped`.

## Mechanism

`builders/late.py` with `BINO_CLAMP=later`: the selection loop of the round that runs first omits
`<n> OP_MIN`. Nothing else in the script changes.

## Soundness

The round that runs first (the last one listed, round 1) no longer clamps its indexes. The clamp
exists so that an index cannot reach a signature outside its own pool. Whether anything
selectable lies below a pool depends on the layout, and in the late layout nothing does for the
first round to run:

1. Directly below round 1's signatures are the commitment tables. A commitment is 20 bytes of
   hash output and not a strictly encoded signature; the evaluator refuses an instance that
   holds any signature-shaped push outside its pools. An index landing there makes the multisig
   fail on encoding.
2. Below the tables is the unlocking script, which the spender controls. An index landing there
   can fetch a signature of the spender's choosing, and the commitment fetched for it, one
   constant further down, is the spender's too. That iteration passes. But it removed two items
   from the witness and none from the tables, so the tables are two items taller than every
   later constant depth assumes, and each later fetch from the witness lands two items too
   shallow. If any iteration remains, its index fetch lands on a commitment, which is not a
   number. If none remains, the puzzle signature can be placed two slots up, but the `t` key
   fetches then take the keys two slots up and, last, the two items above the witness: the two
   deepest commitments of round 0's table. Those become two of the multisig's keys. They are
   constants, they are not public keys, and each is matched against a signature that must
   verify under it. The multisig fails.
3. No iteration can undo the offset: each removes exactly one item at the index's depth and one
   at a constant below it, so an out-of-range iteration never shortens a table.

Round 0 runs second, with the signatures round 1 left behind lying directly below its pool. It
keeps its clamp: the defect test `no-clamp` shows the selection an unclamped index makes there.

The audit exercises both halves of this: every index is swept over every depth, with and
without signatures planted under the witness, by a spender who can open any commitment and can
set an unlocking item to whatever an equality compares it with. On public lanes every accepted
alteration kept the declared structure. A copy of this builder with the clamp removed from
every round passed an earlier audit and is refused by the present one. The accepted spend
there took a signature the previous round had not selected, which needs an unclamped round
that runs after another; here the only unclamped round runs first. That is a search and the
argument above is prose; this instance needs a maintainer's reading before it is relied on,
and the argument depends on properties of this layout (what lies below the first pool, and
that two non-key constants sit directly above the witness) that a variant could lose.

## Experiments

| | Bytes | Opcodes | Work | Security |
| --- | ---: | ---: | ---: | ---: |
| `paper-pin6` | 9,345 | 199 | 2^52.246 | 88.411 |
| `late-pools-pin6` | 9,289 | 199 | 2^52.235 | 88.411 |
| this | 9,265 | 191 | 2^52.235 | 88.411 |

Score 8,530,623,757 against 9,033,284,929 for the baseline: 5.6% lower, all of it the eight operations. Work is pinning on this track and does not move.

## Result and next steps

This instance is at or below the baseline on every count and has the lowest score on this track. An instance with a 48-bit round puzzle and 5-byte pinning (`late-round48`) had a lower score on the first board under the old model BH-SEC-1. It was removed: BH-SEC-2 caps a level at the work of two pinning puzzles, 80.011 bits with 5-byte pinning, below this track's floor of 88.4.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
