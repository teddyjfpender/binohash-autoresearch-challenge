# Late pools, first round unclamped, two rounds of 120-choose-8

The first instance below 199 operations: 191, at the paper's parameters.

## Goal and starting point

`standard/late-pools`. The paper's script uses 199 of 201 operations; 16 of them are index clamps. The clamp turned out to be necessary in general (removing it everywhere is one of the evaluator's refused defects), so the question became where exactly it is needed.

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
| `late-pools` | 9,293 | 199 | 2^46.081 | 80.011 |
| this | 9,269 | 191 | 2^46.121 | 80.011 |

Score 123,217,063 against 125,190,801 for `late-pools` and 198,865,940 for the baseline. Work is 0.04 bits higher than `late-pools`: the script is 24 bytes shorter, which moves round 0's pool across a SHA-256 block boundary and costs its attempts one more compression (10 instead of 9). Compressions per attempt depend on where a pool falls modulo 64 bytes; nothing here tunes that.

## Result and next steps

Eight operations are free for the application, or for a ninth selection in the unclamped round. An instance that spent them that way (`late-unclamped-116-128`) was recorded on the first board under the old model BH-SEC-1 at 81.55 bits and removed: BH-SEC-2 counts its rounds as 81.03 bits, because an attacker searches only part of an oversized round. The level of this instance is the pinning cap, 80.011 bits against a floor of 80.0; its rounds alone are worth 81.521. Unclamping round 0 as well would need a layout in which round 1 leaves nothing selectable behind.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
