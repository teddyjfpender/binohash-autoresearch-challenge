"""Early openings: the commitments are opened before any signature pool is pushed.

A round's grinding attempt rehashes the sighash preimage from its innermost selected signature
to the end, so every byte that follows a pool is paid for on every attempt. In the paper's loop
(and in `late.py`) that includes the whole selection loop: for each selected element an index
fetch, a commitment fetch, a preimage fetch and a hash comparison, about 19 bytes of script.
Only one of those steps needs the pool: rolling the signature out.

Here a round is split in two phases.

  Phase 1, before any pool is pushed. The round's commitment table is pushed and, for each slot,
  the witness index is copied (`OP_PICK`), the commitment at that depth is rolled out and
  compared with the hash of the revealed preimage. The index stays in the witness.

  Phase 2, after the round's pool is pushed. For each slot the same witness index is rolled up
  and the signature at that depth is rolled out: `<depth> OP_ROLL OP_ROLL`, five bytes. Then the
  multisig is assembled as in the paper.

The two phases walk two tables of the same shape with the same numbers in the same order, so
slot i removes the same element from both. In phase 2 slot i finds the dummy and i selected
signatures above the pool; phase 1 pushes one constant per slot above the commitment table, so
the same number is the right depth in both and no arithmetic is needed. Pushing a constant is
not a counted operation. A selected element costs seven operations in the two phases
(`PICK ROLL ROLL HASH160 EQUALVERIFY` and `ROLL ROLL`) against eight in the paper's loop without
its clamp, and nine with the key: 23 + 9 per selection in all.

No index is clamped. The script is instead laid out so that an index that leaves its table
cannot end in an accepted spend; the NOTES.md of the `early-openings` submissions have the
argument. It needs exactly this layout (table and phase 1 of round 0 first, round 0's puzzle
signature on top of the witness and size-checked there) and at most two rounds, which the
builder enforces.

Knobs:
  BINO_ROUNDS       "n:t" per round, comma separated; round 0's pool is last in the script
  BINO_PIN_BYTES    bytes below 60 of a pinning signature     (default 5)
  BINO_ROUND_BYTES  bytes below 60 of each round's signature  (default 5 for every round)
  BINO_KEY_ROLL     rounds (comma separated numbers, or "none") whose puzzle key is pushed before
                    the pool and rolled into the multisig: one more operation, 30 bytes less
                    behind the pool. Default "none".
  BINO_PAD          "a,b": bytes of padding pushed before the first commitment table and
                    before round 0's pool. Pushes of zero bytes that nothing reads; they move
                    the pools relative to SHA-256's 64-byte blocks. Default "0,0".
  BINO_PIN_ORDER    the order in which the script checks the four pinning puzzles. The puzzles
                    keep their numbers and so their sighash modes. Default "1,2,3,4".
  BINO_PIN_SEP      pinning puzzles (numbers 1 to 4, comma separated, or "none") whose check is
                    preceded by an OP_CODESEPARATOR, which shortens the scriptCode that puzzle
                    and everything after it signs. One operation each. Default "none".
  BINO_PIN_SEP_AT   where in such a check the separator goes: 0 before OP_SIZE, 1 after it, 2
                    after the size, 3 after OP_EQUALVERIFY, 4 after the key. Default 0.
"""
from __future__ import annotations

from bh import script as S
from bh import secp256k1 as ec

from .kit import R_MIN_INVERSE, Asm, dummy_signatures, hash160, knob_ints, specimen_bytes
from .paper import FULL_SIZE, TEST_BYTES, pin_dlog

PREIMAGE_BYTES = 16
PAD_CHUNK = 17  # a padding push is at most 16 bytes of data: never the size of a hash, key or signature


class Stack:
    """The stack as the script will see it on an honest spend, by label. Depths are read from it
    instead of being derived by hand."""

    def __init__(self, asm: Asm, items: list):
        self.asm, self.items = asm, list(items)

    def depth(self, label) -> int:
        return len(self.items) - 1 - self.items.index(label)

    def push(self, label, data: bytes) -> int:
        self.items.append(label)
        return self.asm.push(data)

    def roll(self, label) -> None:
        self.asm.num(self.depth(label))
        self.asm.op(S.OP_ROLL)
        self.items.remove(label)
        self.items.append(label)

    def pick(self, label) -> None:
        self.asm.num(self.depth(label))
        self.asm.op(S.OP_PICK)

    def drop(self, label) -> None:
        self.items.remove(label)


def witness_order(rounds, pin_order=(1, 2, 3, 4)) -> list:
    """Labels of the unlocking script, bottom of the stack first."""
    order = []
    for r in range(len(rounds)):
        order += [("key", r, i) for i in reversed(range(rounds[r][1]))]
    for r in reversed(range(1, len(rounds))):
        order.append(("puzzle", f"round{r}"))
        order += [("pre", r, i) for i in reversed(range(rounds[r][1]))]
        order += [("index", r, i) for i in reversed(range(rounds[r][1]))]
    order += [("pre", 0, i) for i in reversed(range(rounds[0][1]))]
    order += [("index", 0, i) for i in reversed(range(rounds[0][1]))]
    order.append(("puzzle", "round0"))  # on top of everything a round uses: see NOTES.md
    order += [("puzzle", f"pin{i}") for i in reversed(pin_order)]
    return order


def pad(stack: Stack, count: int, tag: str) -> None:
    serial = 0
    while count > 0:
        chunk = min(count, PAD_CHUNK)
        stack.push(("pad", tag, serial), bytes(chunk - 1))
        count -= chunk
        serial += 1


def assemble(rounds, pin_bytes, round_bytes, material, key_roll, pads, pin_order, pin_sep, sep_at) -> tuple[bytes, dict]:
    asm, puzzles = Asm(), []
    stack = Stack(asm, witness_order(rounds, pin_order))
    layout = [{"pool": [0] * n, "commit": [0] * n} for n, _t in rounds]
    asm.push(material["single"][0])
    asm.push(material["single"][1])
    asm.op(S.OP_CHECKSIGVERIFY)
    for i in pin_order:
        dlog = pin_dlog(i, pin_bytes)
        at = sep_at if i in pin_sep else -1
        asm.op(*[S.OP_CODESEPARATOR] * (at == 0), S.OP_SIZE, *[S.OP_CODESEPARATOR] * (at == 1))
        size_at = asm.num(FULL_SIZE - pin_bytes)
        asm.op(*[S.OP_CODESEPARATOR] * (at == 2), S.OP_EQUALVERIFY, *[S.OP_CODESEPARATOR] * (at == 3))
        key_at = asm.push(ec.compressed(ec.mul(dlog)))
        asm.op(*[S.OP_CODESEPARATOR] * (at == 4), S.OP_CHECKSIGVERIFY)
        stack.drop(("puzzle", f"pin{i}"))
        puzzles.append({"id": f"pin{i}", "role": "pin", "key_at": key_at, "size_at": size_at, "dlog": dlog})
    puzzles.sort(key=lambda p: p["id"])  # the judge pairs sighash modes with puzzles in this order
    # Round 0's puzzle signature is now on top of the witness. Its size is checked here, where
    # no round's attempts rehash the check, and it stays where it is until round 0's multisig.
    sizes = {}
    asm.op(S.OP_SIZE)
    sizes[0] = asm.num(FULL_SIZE - round_bytes[0])
    asm.op(S.OP_EQUALVERIFY)

    pad(stack, pads[0], "front")
    # Phase 1: each round's commitment table, opened at the witness indexes. Round 0 first, so
    # that below its table there is nothing but padding and the unlocking script.
    for r, (n, t) in enumerate(rounds):
        for j in reversed(range(n)):
            layout[r]["commit"][j] = stack.push(("commit", r, j), material["rounds"][r]["commits"][j])
        for i in range(t):
            # A witness index is the signature's depth in phase 2: its rank plus the dummy and the
            # i signatures already selected. One constant pushed per slot keeps the same number
            # of items above the table here, so the same number is the commitment's depth.
            stack.items.append(("spacer", r, i))
            asm.num(1)
            stack.pick(("index", r, i))                      # the index stays in the witness
            asm.op(S.OP_ROLL)
            stack.drop(("commit", r, i))
            stack.items.append(("commit", r, i))
            stack.roll(("pre", r, i))
            asm.op(S.OP_HASH160, S.OP_EQUALVERIFY)
            stack.drop(("pre", r, i))
            stack.drop(("commit", r, i))
    # Phase 2: each round's pool, the same indexes, the multisig. Round 0 last.
    keys = {}
    key = ec.compressed(ec.mul(R_MIN_INVERSE))
    for r in sorted(key_roll):                               # ahead of every pool: behind none
        keys[r] = stack.push(("puzzle-key", r), key)
    for r in reversed(range(len(rounds))):
        n, t = rounds[r]
        if r == 0:
            pad(stack, pads[1], "back")
        for j in reversed(range(n)):
            layout[r]["pool"][j] = stack.push(("sig", r, j), material["rounds"][r]["pool"][j][0])
        asm.op(S.OP_0)
        stack.items.append(("dummy", r))
        for i in range(t):
            stack.roll(("index", r, i))
            asm.op(S.OP_ROLL)                                # the signature at the same rank
            stack.drop(("index", r, i))
            stack.drop(("sig", r, i))
            stack.items.append(("sig", r, i))
        stack.roll(("puzzle", f"round{r}"))
        if r != 0:
            asm.op(S.OP_SIZE)
            sizes[r] = asm.num(FULL_SIZE - round_bytes[r])
            asm.op(S.OP_EQUALVERIFY)
        asm.num(t + 1)
        stack.items.append(("count", r, "signatures"))
        for i in range(t):
            stack.roll(("key", r, i))
        if r in key_roll:
            stack.roll(("puzzle-key", r))
        else:
            keys[r] = asm.push(key)
        asm.num(t + 1)
        asm.op(S.OP_CHECKMULTISIG if r == 0 else S.OP_CHECKMULTISIGVERIFY)
        for label in [("dummy", r), ("puzzle", f"round{r}"), ("count", r, "signatures")]:
            stack.drop(label)                                # the multisig consumes all it was given
        for i in range(t):
            stack.drop(("sig", r, i))
            stack.drop(("key", r, i))
        if r in key_roll:
            stack.drop(("puzzle-key", r))
    for r in range(len(rounds)):
        puzzles.append({"id": f"round{r}", "role": "round", "key_at": keys[r], "size_at": sizes[r], "dlog": R_MIN_INVERSE})
    return bytes(asm.code), {"puzzles": puzzles, "layout": layout}


def knob_set(knobs: dict, name: str) -> set[int]:
    text = knobs.get(name, "none")
    return set() if text in ("none", "") else {int(part) for part in text.split(",")}


def build(knobs: dict) -> dict:
    flat = knob_ints(knobs, "BINO_ROUNDS", "120:8,120:8")
    rounds = list(zip(flat[0::2], flat[1::2]))
    pin_bytes = knob_ints(knobs, "BINO_PIN_BYTES", "5")[0]
    round_bytes = knob_ints(knobs, "BINO_ROUND_BYTES", ",".join(["5"] * len(rounds)))
    if len(round_bytes) != len(rounds) or len(flat) % 2:
        raise ValueError("BINO_ROUNDS needs n:t pairs and BINO_ROUND_BYTES one entry per round")
    if not 1 <= len(rounds) <= 2:
        raise ValueError("the early-openings layout is argued for one or two rounds only")
    selections = sum(t for _n, t in rounds)
    if rounds[0][0] - selections < 2 * selections:
        # The argument for leaving out the clamp has a misdirected fetch land on a commitment of
        # round 0's table; each selection can misdirect two, and can remove one commitment.
        raise ValueError("round 0's pool must hold at least three times the selections of all rounds")
    key_roll, pin_sep = knob_set(knobs, "BINO_KEY_ROLL"), knob_set(knobs, "BINO_PIN_SEP")
    pads = knob_ints(knobs, "BINO_PAD", "0,0")
    pin_order = tuple(knob_ints(knobs, "BINO_PIN_ORDER", "1,2,3,4"))
    if not key_roll <= set(range(len(rounds))) or not pin_sep <= {1, 2, 3, 4} or len(pads) != 2 or min(pads) < 0:
        raise ValueError("BINO_KEY_ROLL names rounds, BINO_PIN_SEP pinning puzzles 1 to 4, BINO_PAD two byte counts")
    sep_at = knob_ints(knobs, "BINO_PIN_SEP_AT", "0")[0]
    if sorted(pin_order) != [1, 2, 3, 4] or not 0 <= sep_at <= 4:
        raise ValueError("BINO_PIN_ORDER is a permutation of 1,2,3,4 and BINO_PIN_SEP_AT is 0 to 4")

    signatures = dummy_signatures(sum(n for n, _ in rounds) + 1)
    material, used = {"single": signatures[0], "rounds": []}, 1
    for r, (n, _t) in enumerate(rounds):
        pool = signatures[used:used + n]
        used += n
        preimages = [specimen_bytes(f"early|round{r}|element{j}", PREIMAGE_BYTES) for j in range(n)]
        material["rounds"].append({"pool": pool, "preimages": preimages, "commits": [hash160(p) for p in preimages]})

    locking, prod = assemble(rounds, pin_bytes, round_bytes, material, key_roll, pads, pin_order, pin_sep, sep_at)
    locking_test, test = assemble(rounds, TEST_BYTES, [TEST_BYTES] * len(rounds), material, key_roll, pads, pin_order, pin_sep, sep_at)

    witness = []
    for label in witness_order(rounds, pin_order):
        if label[0] == "puzzle":
            witness.append({"puzzle": label[1]})
        elif label[0] == "index":
            witness.append({"index": [label[1], label[2]], "enc": "rank", "add": label[2] + 1})
        else:
            witness.append({label[0]: [label[1], label[2]]})

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
                "puzzle": f"round{r}", "t": t, "slots": "any",
                "pool": prod["layout"][r]["pool"], "commit": prod["layout"][r]["commit"],
                "keys": [key.hex() for _sig, key in material["rounds"][r]["pool"]],
                "preimages": [p.hex() for p in material["rounds"][r]["preimages"]],
            }
            for r, (_n, t) in enumerate(rounds)
        ],
        "witness": witness,
    }
