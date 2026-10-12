"""Late pools: the paper's construction with every signature pool as late in the script as it can be.

A round's grinding attempt rehashes the sighash preimage from its innermost selected signature
to the end, so what follows a pool in the script is paid for on every attempt. In the paper's
layout the first round's pool is followed by the whole second round, commitments included: 71
compressions per attempt against 9 for the second round.

Here all commitment tables are pushed first, where no round's attempts rehash them. Then each
round pushes its signature pool and runs its selection loop, the rounds in reverse order, so
that round 0 comes last and has nothing behind it but its own loop. An earlier pool still has
the later rounds' pools and loops behind it; that is inherent, since a scriptCode always runs to
the end of the script. Give the round with the larger pool the lower number.

The selection loop, the index clamp, the pinning section and the multisig are the paper's
(`paper.py`); only depths change. Preimages are 16 bytes, the minimum the spec allows.

Knobs:
  BINO_ROUNDS       "n:t" per round, comma separated          (default 120:8,120:8)
  BINO_PIN_BYTES    bytes below 60 of a pinning signature     (default 5)
  BINO_ROUND_BYTES  bytes below 60 of each round's signature  (default 5 for every round)
  BINO_CLAMP        "all": every round clamps its indexes, as the paper does (default).
                    "later": the round that runs first does not. Below its pool there are only
                    commitments, which are not signatures, and the witness.
"""
from __future__ import annotations

from bh import script as S
from bh import secp256k1 as ec

from .kit import R_MIN_INVERSE, Asm, dummy_signatures, hash160, knob_ints, specimen_bytes
from .paper import FULL_SIZE, TEST_BYTES, pin_dlog

PREIMAGE_BYTES = 16


def assemble(rounds, pin_bytes, round_bytes, material, clamp_first=True) -> tuple[bytes, dict]:
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
    # Every commitment table, round 0's deepest. No round's attempts rehash these.
    for r, (n, _t) in enumerate(rounds):
        for j in reversed(range(n)):
            layout[r]["commit"][j] = asm.push(material["rounds"][r]["commits"][j])
    round_puzzles = {}
    for r in reversed(range(len(rounds))):
        n, t = rounds[r]
        # Signatures left by the rounds already run, and the commitments still in their tables.
        left = sum(rounds[j][0] - rounds[j][1] for j in range(r + 1, len(rounds)))
        below = sum(rounds[j][0] for j in range(r))  # tables of the rounds still to run
        for j in reversed(range(n)):
            layout[r]["pool"][j] = asm.push(material["rounds"][r]["pool"][j][0])
        asm.op(S.OP_0)
        for i in range(t):
            asm.num(2 * n - i + 1 + 2 * left + below)        # the next index, from the witness
            asm.op(S.OP_ROLL)
            if clamp_first or r != len(rounds) - 1:
                asm.num(n)                                   # at most this round's deepest signature
                asm.op(S.OP_MIN)
            asm.op(S.OP_DUP)
            asm.num(n + 1 - i + 2 * left)                    # the same element's commitment
            asm.op(S.OP_ADD, S.OP_ROLL)
            asm.num(2 * n + t - 2 * i + 1 + 2 * left + below)  # the next preimage, from the witness
            asm.op(S.OP_ROLL, S.OP_HASH160, S.OP_EQUALVERIFY)
            asm.op(S.OP_ROLL)                                # the selected signature
        asm.num(2 * n + 1 + 2 * left + below)                # the puzzle signature
        asm.op(S.OP_ROLL, S.OP_SIZE)
        size_at = asm.num(FULL_SIZE - round_bytes[r])
        asm.op(S.OP_EQUALVERIFY)
        asm.num(t + 1)
        for _ in range(t):
            asm.num(2 * n + 2 + 2 * left + below)            # the deepest remaining key, from the witness
            asm.op(S.OP_ROLL)
        key_at = asm.push(ec.compressed(ec.mul(R_MIN_INVERSE)))
        asm.num(t + 1)
        asm.op(S.OP_CHECKMULTISIG if r == 0 else S.OP_CHECKMULTISIGVERIFY)
        round_puzzles[r] = {"id": f"round{r}", "role": "round", "key_at": key_at, "size_at": size_at, "dlog": R_MIN_INVERSE}
    puzzles += [round_puzzles[r] for r in range(len(rounds))]
    return bytes(asm.code), {"puzzles": puzzles, "layout": layout}


def build(knobs: dict) -> dict:
    flat = knob_ints(knobs, "BINO_ROUNDS", "120:8,120:8")
    rounds = list(zip(flat[0::2], flat[1::2]))
    pin_bytes = knob_ints(knobs, "BINO_PIN_BYTES", "5")[0]
    round_bytes = knob_ints(knobs, "BINO_ROUND_BYTES", ",".join(["5"] * len(rounds)))
    if len(round_bytes) != len(rounds) or len(flat) % 2:
        raise ValueError("BINO_ROUNDS needs n:t pairs and BINO_ROUND_BYTES one entry per round")

    signatures = dummy_signatures(sum(n for n, _ in rounds) + 1)
    material, used = {"single": signatures[0], "rounds": []}, 1
    for r, (n, _t) in enumerate(rounds):
        pool = signatures[used:used + n]
        used += n
        preimages = [specimen_bytes(f"late|round{r}|element{j}", PREIMAGE_BYTES) for j in range(n)]
        material["rounds"].append({"pool": pool, "preimages": preimages, "commits": [hash160(p) for p in preimages]})

    clamp = knobs.get("BINO_CLAMP", "all")
    if clamp not in ("all", "later"):
        raise ValueError("BINO_CLAMP is 'all' or 'later'")
    locking, prod = assemble(rounds, pin_bytes, round_bytes, material, clamp == "all")
    locking_test, test = assemble(rounds, TEST_BYTES, [TEST_BYTES] * len(rounds), material, clamp == "all")

    # Unlocking script, bottom to top: round 0's block deepest (it runs last), then the pinning
    # signatures with the first puzzle's on top.
    witness = []
    for r, (_n, t) in enumerate(rounds):
        witness.append({"puzzle": f"round{r}"})
        witness += [{"key": [r, i]} for i in range(t)]
        witness += [{"pre": [r, i]} for i in reversed(range(t))]
        witness += [{"index": [r, i], "enc": "rank", "add": i + 1} for i in reversed(range(t))]
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
                "puzzle": f"round{r}", "t": t, "slots": "any",
                "pool": prod["layout"][r]["pool"], "commit": prod["layout"][r]["commit"],
                "keys": [key.hex() for _sig, key in material["rounds"][r]["pool"]],
                "preimages": [p.hex() for p in material["rounds"][r]["preimages"]],
            }
            for r, (_n, t) in enumerate(rounds)
        ],
        "witness": witness,
    }
