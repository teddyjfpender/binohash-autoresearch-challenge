# Late pools, first round unclamped, 116-choose-8 and 128-choose-9

The lowest score found on the `standard` track: 1.93 times below the baseline, at 128 bytes more than it.

## Goal and starting point

`standard/late-unclamped` and `standard/late-pools-120-172`. The second showed that one plentiful round is worth 0.3 bits of work but needs 172 elements at eight selections. The first freed eight operations in the round that runs first.

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
| `late-pools-120-172` | 10,929 | 199 | 2^45.777 | 81.524 |
| this | 9,477 | 201 | 2^45.757 | 81.546 |

Score 103,014,088. Not clamping round 1 makes a selection there cost 10 operations instead of 11, so nine selections cost 90 where eight clamped ones cost 88, and the total is 201. Nine selections reach 2^44.1 selections with 128 elements where eight needed 172, which is 1,364 bytes. Round 0 shrinks to 116 to keep the level above the floor; 2.3 transactions are tried per spend.

## Result and next steps

The opcode budget is now exhausted, which is the opposite of what an application wants; `late-unclamped` is the instance to take when room matters. Every further selection in round 1 would shrink it by another 20 elements or so at 10 operations each.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
