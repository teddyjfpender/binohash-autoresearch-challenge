"""Paired tables: one table of (signature, commitment) pairs per round, a height marker under it.

Each round pushes ONE table in which every pool signature is followed directly by its own
commitment, so on the stack the commitment of an element lies exactly one item above its
signature. A selection is then one index used twice without arithmetic:

    <w> ROLL            the index k, from the top of the unlocking script
    DUP PICK            a copy of the item k-1 below: the commitment (it stays in the table)
    <w> ROLL            the preimage, from the top of the unlocking script
    HASH160 EQUALVERIFY
    ROLL                the item k below: the signature directly under that commitment

OP_PICK reads one item shallower than the OP_ROLL that follows it, because the index itself is
still on the stack for the first and gone for the second. That is seven operations where the
rolled-subset loop takes nine (it needs `<n> MIN` and `<c> ADD`), and nine per selected element
with its key against eleven.

Nothing clamps an index. Instead:

  - Within a table the only item directly below a commitment is its own signature (or, once that
    signature has been taken, another commitment), so an opened commitment can only release its
    own signature, in any order and for any index.
  - Every round but the first to run keeps its puzzle's size constant UNDER its table and fetches
    it with a constant-depth OP_PICK for the size check. Rolling anything from below that
    constant (another round's leftovers, the unlocking script) leaves the constant one item
    deeper than the OP_PICK expects, and the size check compares the signature's size with a
    table element instead. One operation per round replaces one per selected element.
  - The unlocking script is consumed strictly from its top by constant-depth rolls. In the round
    that runs first, an index that reaches the unlocking script removes an item from it and none
    from the table, so the next constant-depth roll lands on the deepest item of the table, a
    nine-byte signature or a twenty-byte commitment, where an index or a puzzle signature is
    expected.

Rounds run in the order listed and their tables appear in the script in that order, so the last
round listed has the least script behind its pool and the cheapest grinding attempts.

Knobs:
  BINO_ROUNDS       "n:t" per round, comma separated, in script order   (default 100:6,100:6,100:7)
  BINO_PIN_BYTES    bytes below 60 of a pinning signature                (default 4)
  BINO_ROUND_BYTES  bytes below 60 of each round's signature             (default 4 for every round)
  BINO_MARKERS      "later": every round but the first to run (default); "all": every round
"""
from __future__ import annotations

from bh import script as S
from bh import secp256k1 as ec

from .kit import R_MIN_INVERSE, Asm, dummy_signatures, hash160, knob_ints, specimen_bytes
from .paper import FULL_SIZE, TEST_BYTES, pin_dlog

PREIMAGE_BYTES = 16


def assemble(rounds, pin_bytes, round_bytes, material, witness_items, markers_all=False) -> tuple[bytes, dict]:
    asm, puzzles = Asm(), []
    layout = [{"pool": [0] * n, "commit": [0] * n} for n, _t in rounds]
    # `size` is the number of stack items, `wit` how many of them are unlocking items not yet
    # consumed. The unlocking script is consumed from its top, so its top item is always
    # `size - wit` items below the top of the stack.
    state = {"size": witness_items, "wit": witness_items}

    def fetch():
        asm.num(state["size"] - state["wit"])
        asm.op(S.OP_ROLL)
        state["wit"] -= 1

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
        state["size"] -= 1
        state["wit"] -= 1
        puzzles.append({"id": f"pin{i}", "role": "pin", "key_at": key_at, "size_at": size_at, "dlog": dlog})

    for r, (n, t) in enumerate(rounds):
        marker = markers_all or r > 0
        size_at = None
        if marker:
            size_at = asm.num(FULL_SIZE - round_bytes[r])     # the height marker, and the puzzle's size
            state["size"] += 1
        marker_floor = state["size"]                          # stack items up to and including the marker
        marker_wit = state["wit"]
        for j in reversed(range(n)):
            layout[r]["pool"][j] = asm.push(material["rounds"][r]["pool"][j][0])
            layout[r]["commit"][j] = asm.push(material["rounds"][r]["commits"][j])
        asm.op(S.OP_0)                                        # the multisig's dummy
        state["size"] += 2 * n + 1
        for _ in range(t):
            fetch()                                           # the index k
            asm.op(S.OP_DUP, S.OP_PICK)                       # the commitment, k-1 below
            state["size"] += 1
            fetch()                                           # the preimage
            asm.op(S.OP_HASH160, S.OP_EQUALVERIFY)
            asm.op(S.OP_ROLL)                                 # the signature, k below
            state["size"] -= 3                                # commitment copy, hash and index are gone
        fetch()                                               # the puzzle signature
        asm.op(S.OP_SIZE)
        if marker:
            # Items above the marker: those pushed since, plus the unlocking items rolled up since.
            above = (state["size"] + 1 - marker_floor) + (marker_wit - state["wit"])
            asm.num(above)
            asm.op(S.OP_PICK)
        else:
            size_at = asm.num(FULL_SIZE - round_bytes[r])
        asm.op(S.OP_EQUALVERIFY)
        asm.num(t + 1)
        state["size"] += 1
        for _ in range(t):
            fetch()                                           # the keys, the first selection's first
        key_at = asm.push(ec.compressed(ec.mul(R_MIN_INVERSE)))
        asm.num(t + 1)
        last = r == len(rounds) - 1
        asm.op(S.OP_CHECKMULTISIG if last else S.OP_CHECKMULTISIGVERIFY)
        state["size"] -= 2 * t + 3                            # dummy, t+1 signatures, count, t keys
        puzzles.append({"id": f"round{r}", "role": "round", "key_at": key_at, "size_at": size_at,
                        "dlog": R_MIN_INVERSE})
    return bytes(asm.code), {"puzzles": puzzles, "layout": layout}


def build(knobs: dict) -> dict:
    flat = knob_ints(knobs, "BINO_ROUNDS", "100:6,100:6,100:7")
    rounds = list(zip(flat[0::2], flat[1::2]))
    pin_bytes = knob_ints(knobs, "BINO_PIN_BYTES", "4")[0]
    round_bytes = knob_ints(knobs, "BINO_ROUND_BYTES", ",".join(["4"] * len(rounds)))
    if len(round_bytes) != len(rounds) or len(flat) % 2:
        raise ValueError("BINO_ROUNDS needs n:t pairs and BINO_ROUND_BYTES one entry per round")
    markers = knobs.get("BINO_MARKERS", "later")
    if markers not in ("later", "all"):
        raise ValueError("BINO_MARKERS is 'later' or 'all'")

    signatures = dummy_signatures(sum(n for n, _ in rounds) + 1)
    material, used = {"single": signatures[0], "rounds": []}, 1
    for r, (n, _t) in enumerate(rounds):
        pool = signatures[used:used + n]
        used += n
        preimages = [specimen_bytes(f"pairs|round{r}|element{j}", PREIMAGE_BYTES) for j in range(n)]
        material["rounds"].append({"pool": pool, "preimages": preimages, "commits": [hash160(p) for p in preimages]})

    # The unlocking script in the order the locking script consumes it, then reversed: the first
    # item consumed is on top. Element 0 of a table is its shallowest pair; a selection is listed
    # deepest element first, so nothing above a selected pair has moved when its index is used.
    consumed = [{"puzzle": f"pin{i}"} for i in (1, 2, 3, 4)]
    for r, (_n, t) in enumerate(rounds):
        for i in range(t):
            consumed.append({"index": [r, i], "enc": "abs", "mul": 2, "add": i + 2})
            consumed.append({"pre": [r, i]})
        consumed.append({"puzzle": f"round{r}"})
        consumed += [{"key": [r, i]} for i in range(t)]
    witness = consumed[::-1]

    locking, prod = assemble(rounds, pin_bytes, round_bytes, material, len(witness), markers == "all")
    locking_test, test = assemble(rounds, TEST_BYTES, [TEST_BYTES] * len(rounds), material, len(witness),
                                  markers == "all")
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
                "puzzle": f"round{r}", "t": t, "slots": "descending",
                "pool": prod["layout"][r]["pool"], "commit": prod["layout"][r]["commit"],
                "keys": [key.hex() for _sig, key in material["rounds"][r]["pool"]],
                "preimages": [p.hex() for p in material["rounds"][r]["preimages"]],
            }
            for r, (_n, t) in enumerate(rounds)
        ],
        "witness": witness,
    }
