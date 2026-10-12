# Late pools, first round unclamped, 104-choose-8 and 88-choose-9

The smallest instance found on the `standard` track: 7,854 bytes, 16% below the baseline, with less work than the baseline.

## Goal and starting point

`standard/late-pools-108-120` and `standard/late-unclamped`. The ninth selection that the unclamped round can afford is spent here on a smaller pool instead of a more plentiful one.

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
without signatures planted under the witness, by a spender who can open any commitment. On
public lanes every accepted alteration kept the declared structure. That is a search and the
argument above is prose; this instance needs a maintainer's reading before it is relied on,
and the argument depends on properties of this layout (what lies below the first pool, and
that two non-key constants sit directly above the witness) that a variant could lose.

## Experiments

| | Bytes | Opcodes | Work | Security |
| --- | ---: | ---: | ---: | ---: |
| `late-pools-108-120` | 8,921 | 199 | 2^46.244 | 81.643 |
| this | 7,854 | 201 | 2^46.559 | 81.959 |

Score 148,847,895. 88-choose-9 has 2^39.1 selections, nearly what 120-choose-8 has, in 32 fewer elements: 992 bytes. Both rounds are scarce (a solution 21% and 40% of the time), so 11.9 transactions are tried per spend, each costing one pinning puzzle; that is where the 0.3 bits over `late-pools-108-120` go.

## Result and next steps

Bytes are 31 per pool element and the opcode budget is spent. Below this, the count has to come from fewer bytes per element.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
