# Late pools, two rounds of 120-choose-8

The paper's construction with its published parameters and a different layout. Same opcodes,
56 bytes fewer, 0.66 bits less work: every count at or below the baseline's.

## Goal and starting point

`standard/paper-two-round` (instance `e71f...`, see the starting board). Its work is dominated by
the first round's attempts: 71 SHA-256 compressions each, against 9 for the second round. The
goal was to remove that asymmetry without touching the construction.

## Mechanism

A grinding attempt rehashes the sighash preimage from the innermost selected signature to the
end. In the paper's layout the first round's pool is followed by the whole second round: 120
commitments (2,520 bytes), 120 signatures (1,200 bytes) and its loop. The commitments are never
removed by FindAndDelete, so nothing requires them to sit near a pool.

`builders/late.py` pushes both commitment tables first, then round 1's signatures and loop, then
round 0's signatures and loop. Round 0 has only its own loop behind it; round 1 has round 0's
pool and loop. The selection loop is the paper's operation for operation. Only the constants
change: the depth of a commitment now skips the signatures left by the round already run, and
witness items are fetched past the tables of rounds still to run.

Preimages are 16 bytes instead of 20, the minimum the spec allows; that is the 64 bytes saved in
the unlocking script. The locking script is 8 bytes longer (wider depth constants).

## Soundness

Nothing the security argument uses has changed.

- Pinning is byte for byte the paper's section.
- Each round's multisig is still `t+1` of `t+1` with the puzzle key last, and the puzzle
  signature is still size-checked with `OP_EQUALVERIFY`.
- Each index is still clamped to its own pool with `<n> OP_MIN` before it is used. What lies
  below a pool is now another round's pool or the signatures a round left behind, so the clamp
  matters as much as before: the evaluator's defect test `no-clamp` shows what happens without it.
- Each selected signature is still opened against the commitment at the same rank by
  `OP_HASH160 ... OP_EQUALVERIFY`. The commitment's depth is the signature's depth plus a
  constant that counts exactly the items between the two tables at that iteration: the rest of
  this round's signatures, the signatures left by rounds already run, and their depleted
  commitment tables, which sit above this round's because they were pushed later.
- Both pools lie inside the scriptCode of both multisigs (there is no `OP_CODESEPARATOR`), and
  a multisig removes only the signatures passed to it, so the rounds stay independent.

The audit agrees: on public lanes, every altered spend it accepted had the declared structure.

## Experiments

| | Bytes | Opcodes | Work | Security | Compressions per attempt |
| --- | ---: | ---: | ---: | ---: | --- |
| `paper-two-round` | 9,349 | 199 | 2^46.740 | 80.011 | 71 and 9 |
| this | 9,293 | 199 | 2^46.081 | 80.011 | 9 and 32 |

Score 125,190,801 against 198,865,940: 1.59 times lower. Security is the level under BH-SEC-2:
the pinning cap of 80.011 bits for both instances, whose rounds alone are worth 81.521.

What did not work, or did not help:

- **Both pools last.** One pool always has the other behind it, because a scriptCode runs to
  the end of the script. Interleaving the two pools would even the tails out, but a round's
  `OP_ROLL` would then shift the other round's depths by an amount that depends on its
  selection, which the witness format cannot express and the script cannot correct for free.
- **Interleaving each signature with its commitment** to fetch both with one index. The second
  fetch is off by one from the first whichever of the two is on top, and fixing that costs the
  operation (`OP_SWAP` or `OP_1SUB`) that the removed `OP_ADD` saved. Nine operations per
  element either way, and the pool then spans three times the bytes.

## Result and next steps

A strict improvement on the baseline at the same parameters. What remains in the work: round
1's attempts still rehash round 0's 1,200-byte pool (19 of its 32 compressions), and 3.5
transactions are tried per spend. A larger second pool lowers the second. An instance tuned
that way against the old model BH-SEC-1 (`late-pools-120-172`) was removed from the board:
it had been credited 81.52 bits and its rounds are worth 81.04 under BH-SEC-2, because an
attacker searches only part of an oversized round. With the floor now at 80.0 and the level
held at the cap, pool sizes on this track trade bytes against retries.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
