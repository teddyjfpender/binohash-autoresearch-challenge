"""Paired pools under a canary: each signature directly under its own commitment, selected by
position alone, and the round's puzzle signature beneath the pool in place of a clamp.

A variant of architecture `paired-table` (`pairs.py`). The table of pairs and the selection are
the same. What differs is how an index is confined to its pool: `pairs.py` keeps a size constant
under the table and reads it back with a constant-depth `OP_PICK`; here the puzzle signature
itself lies under the pool and is rolled out at a constant depth.

The paper's loop spends eleven counted operations on a selected element. Two of them exist only
because signatures and commitments are separate tables: `OP_ADD`, to turn a signature's depth
into its commitment's, and `<n> OP_MIN`, to keep the index inside the pool. Here a round pushes
one table of pairs, element 0 on top:

    ... <sig j> <commit j> ... <sig 0> <commit 0>

and the loop is

    <d> OP_ROLL                             the index x, from the unlocking script
    OP_DUP OP_PICK                          a copy of the item x-1 below the index
    <d'> OP_ROLL OP_HASH160 OP_EQUALVERIFY  it is the hash of a revealed preimage
    OP_ROLL                                 the item directly beneath it moves to the top

`OP_PICK` reads with the index still on the stack and `OP_ROLL` without it, so the same number
names two adjacent items: the one that was opened and the one beneath it. The commitment is
copied, not removed, so no depth needs correcting. Seven operations in the loop, nine per
element with its key.

Binding is by adjacency. Whatever was opened, the item taken is the one under it; in a table of
pairs that is the element's own signature or, when that signature is gone, another commitment,
which is not a signature. What keeps an index inside the round's own pool is not a clamp but a
count: the round's puzzle signature lies directly beneath the pool (the first round to run finds
it on top of the unlocking script; a later round rolls it there before pushing its pool, one
operation per round) and is fetched afterwards at a constant depth. Every element taken from
anywhere but the pool leaves the pool one item taller, so that fetch returns a pool item, and
`OP_SIZE <size> OP_EQUALVERIFY` refuses it. NOTES.md of `standard/paired-canary-92-102` has the
argument, for two rounds with round 0 split.

Selections are listed in ascending element order, shallowest first: each selection removes one
item above the later ones and adds one on top, so an element's depth is `2 e + 2` in every slot.

A paired pool spans 31 bytes per element, and every pool behind another one is rehashed by the
other round's grinding attempts. `BINO_SPLIT` lists rounds that keep the paper's two tables
instead: their commitments go ahead of every pool, the index is a rank used in both tables
(`OP_DUP <k> OP_ADD OP_ROLL` for the commitment), and the same canary replaces the clamp. That
is ten operations per element, and worth it for a round whose pool is behind an expensive one.

Operations: 13 for pinning; per round `9 t + 5`, or `10 t + 5` if split; one more for each round
that has anything of the script's beneath its pool (every round but the first to run, and that
one too when a split round's commitment table is on the stack).

Knobs:
  BINO_ROUNDS       "n:t" per round, comma separated; the last one listed runs first and
                    round 0's pool is last in the script              (default 76:7,104:6,104:6)
  BINO_PIN_BYTES    bytes below 60 of a pinning signature             (default 4, which the
                    pinning cap prices at 64 bits; a submission sets 5 or more)
  BINO_ROUND_BYTES  bytes below 60 of each round's signature          (default 4 for every round)
  BINO_SPLIT        round numbers that keep two tables, e.g. "0"      (default none)
"""
from __future__ import annotations

from bh import script as S
from bh import secp256k1 as ec

from .kit import R_MIN_INVERSE, Asm, dummy_signatures, hash160, knob_ints, specimen_bytes
from .paper import FULL_SIZE, TEST_BYTES, pin_dlog

PREIMAGE_BYTES = 16


def assemble(rounds, pin_bytes, round_bytes, material, split=frozenset()) -> tuple[bytes, dict]:
    asm, puzzles = Asm(), []
    layout = [{"pool": [0] * n, "commit": [0] * n} for n, _t in rounds]
    asm.push(material["single"][0])
    asm.push(material["single"][1])
    asm.op(S.OP_CHECKSIGVERIFY)
    for i in range(1, 5):
        dlog = pin_dlog(i, pin_bytes)
        asm.op(S.OP_SIZE)
        size_at = asm.num(FULL_SIZE - pin_bytes)
        asm.op(S.OP_EQUALVERIFY)
        key_at = asm.push(ec.compressed(ec.mul(dlog)))
        asm.op(S.OP_CHECKSIGVERIFY)
        puzzles.append({"id": f"pin{i}", "role": "pin", "key_at": key_at, "size_at": size_at, "dlog": dlog})
    # Commitment tables of the split rounds, where no round's attempts rehash them.
    above = 0  # items the script has put or left above the unlocking script
    table_top = {}  # per split round: how many of those items its commitment table ends at
    for r, (n, _t) in enumerate(rounds):
        if r in split:
            for j in reversed(range(n)):
                layout[r]["commit"][j] = asm.push(material["rounds"][r]["commits"][j])
            above += n
            table_top[r] = above
    round_puzzles = {}
    for r in reversed(range(len(rounds))):
        n, t = rounds[r]
        if above:
            # The puzzle signature is on top of what is left of the unlocking script. Put it
            # directly beneath this round's pool, above everything the script has left so far.
            asm.num(above)
            asm.op(S.OP_ROLL)
        for j in reversed(range(n)):
            layout[r]["pool"][j] = asm.push(material["rounds"][r]["pool"][j][0])
            if r not in split:
                layout[r]["commit"][j] = asm.push(material["rounds"][r]["commits"][j])
        asm.op(S.OP_0)
        if r in split:
            # The paper's two tables without the clamp: the index is a rank in both and both lose
            # the element, so the commitment table shrinks under the fetches.
            gap = above - table_top[r]  # between this round's table and its puzzle signature
            if gap < t:
                # The argument that a commitment fetch cannot reach back into the pool counts on
                # at least t items between the table and the pool.
                raise ValueError("a split round needs another round's leftovers between its table and its pool: "
                                 "do not split the round that runs first")
            for i in range(t):
                asm.num(above - i + n + t + 2)       # the next index
                asm.op(S.OP_ROLL, S.OP_DUP)
                asm.num(n + 2 + gap - i)             # the commitment of the same rank
                asm.op(S.OP_ADD, S.OP_ROLL)
                asm.num(above - i + n + t + 3)       # the next preimage
                asm.op(S.OP_ROLL, S.OP_HASH160, S.OP_EQUALVERIFY)
                asm.op(S.OP_ROLL)                    # the signature of that rank
            beneath, keys = n + 1, above + n + 2
            left = n - 2 * t
        else:
            # Above the unlocking script: what the script left, the puzzle signature if it was
            # rolled up, the 2n items of the pool and the dummy. A selection moves one of them to
            # the top, so the count does not change. On top of the unlocking script: the puzzle
            # signature unless it was rolled up, then the t keys, then the next index.
            fetch = above + 2 * n + 2 + t
            for _ in range(t):
                asm.num(fetch)              # the next index
                asm.op(S.OP_ROLL)
                asm.op(S.OP_DUP, S.OP_PICK)  # the commitment at that depth, left in place
                asm.num(fetch + 2)          # the next preimage, past the index and the copy
                asm.op(S.OP_ROLL, S.OP_HASH160, S.OP_EQUALVERIFY)
                asm.op(S.OP_ROLL)           # the signature directly beneath the commitment
            beneath, keys = 2 * n + 1, above + 2 * n + 2 + t
            left = 2 * n - t
        asm.num(beneath)                    # the item directly beneath the pool: the puzzle signature
        asm.op(S.OP_ROLL, S.OP_SIZE)
        size_at = asm.num(FULL_SIZE - round_bytes[r])
        asm.op(S.OP_EQUALVERIFY)
        asm.num(t + 1)
        for _ in range(t):
            asm.num(keys)                   # the deepest remaining key
            asm.op(S.OP_ROLL)
        key_at = asm.push(ec.compressed(ec.mul(R_MIN_INVERSE)))
        asm.num(t + 1)
        asm.op(S.OP_CHECKMULTISIG if r == 0 else S.OP_CHECKMULTISIGVERIFY)
        round_puzzles[r] = {"id": f"round{r}", "role": "round", "key_at": key_at, "size_at": size_at, "dlog": R_MIN_INVERSE}
        above += left
    puzzles += [round_puzzles[r] for r in range(len(rounds))]
    return bytes(asm.code), {"puzzles": puzzles, "layout": layout}


def build(knobs: dict) -> dict:
    flat = knob_ints(knobs, "BINO_ROUNDS", "76:7,104:6,104:6")
    rounds = list(zip(flat[0::2], flat[1::2]))
    pin_bytes = knob_ints(knobs, "BINO_PIN_BYTES", "4")[0]
    round_bytes = knob_ints(knobs, "BINO_ROUND_BYTES", ",".join(["4"] * len(rounds)))
    if len(round_bytes) != len(rounds) or len(flat) % 2:
        raise ValueError("BINO_ROUNDS needs n:t pairs and BINO_ROUND_BYTES one entry per round")
    if any(t < 1 or n < 2 * t for n, t in rounds):
        raise ValueError("a paired pool needs n >= 2t: the depth count relies on the pool outnumbering a round's selections")

    signatures = dummy_signatures(sum(n for n, _ in rounds) + 1)
    material, used = {"single": signatures[0], "rounds": []}, 1
    for r, (n, _t) in enumerate(rounds):
        pool = signatures[used:used + n]
        used += n
        preimages = [specimen_bytes(f"paired|round{r}|element{j}", PREIMAGE_BYTES) for j in range(n)]
        material["rounds"].append({"pool": pool, "preimages": preimages, "commits": [hash160(p) for p in preimages]})

    split = frozenset(knob_ints(knobs, "BINO_SPLIT", "")) if knobs.get("BINO_SPLIT") else frozenset()
    if not split <= set(range(len(rounds))):
        raise ValueError("BINO_SPLIT lists round numbers")
    locking, prod = assemble(rounds, pin_bytes, round_bytes, material, split)
    locking_test, test = assemble(rounds, TEST_BYTES, [TEST_BYTES] * len(rounds), material, split)

    # Unlocking script, bottom to top. Round 0 runs last, so its block is deepest. Within a block
    # the preimages and indexes are deepest, slot 0 uppermost; then the keys, slot 0 deepest; then
    # the puzzle signature, which is therefore on top when its round begins. The four pinning
    # signatures are above everything, the first puzzle's on top.
    witness = []
    for r, (_n, t) in enumerate(rounds):
        for i in reversed(range(t)):
            witness.append({"pre": [r, i]})
            if r in split:
                witness.append({"index": [r, i], "enc": "rank", "add": i + 1})
            else:
                witness.append({"index": [r, i], "enc": "abs", "mul": 2, "add": 2})
        witness += [{"key": [r, i]} for i in range(t)]
        witness.append({"puzzle": f"round{r}"})
    witness += [{"puzzle": f"pin{i}"} for i in (4, 3, 2, 1)]

    return {
        "schema": "bh-instance-v1",
        "locking": locking.hex(),
        "locking_test": locking_test.hex(),
        "puzzles": [
            {**p, "dlog": f"{p['dlog']:064x}", "dlog_test": f"{q['dlog']:064x}"}
            for p, q in zip(prod["puzzles"], test["puzzles"])
        ],
        "rounds": [
            {
                "puzzle": f"round{r}", "t": t, "slots": "any" if r in split else "ascending",
                "pool": prod["layout"][r]["pool"], "commit": prod["layout"][r]["commit"],
                "keys": [key.hex() for _sig, key in material["rounds"][r]["pool"]],
                "preimages": [p.hex() for p in material["rounds"][r]["preimages"]],
            }
            for r, (_n, t) in enumerate(rounds)
        ],
        "witness": witness,
    }
