"""The construction of the Binohash paper, as published.

Transaction pinning is Appendix A: an explicit SIGHASH_SINGLE check and four signature-size
puzzles whose keys give them disjoint sighash targets. Each nonce-extraction round is the
Appendix B listing: n commitments and n nine-byte signatures are pushed, t of them are selected
by OP_ROLL through witness indexes, each selection is opened against its HASH160 commitment, and
the selection is verified together with the puzzle signature by one OP_CHECKMULTISIG.

Knobs:
  BINO_ROUNDS       "n:t" per round, comma separated          (default 120:8,120:8)
  BINO_PIN_BYTES    bytes below 60 of a pinning signature     (default 5)
  BINO_ROUND_BYTES  bytes below 60 of each round's signature  (default 5 for every round)
"""
from __future__ import annotations

from bh import script as S
from bh import secp256k1 as ec

from .kit import R_MIN_INVERSE, Asm, dummy_signatures, hash160, knob_ints, specimen_bytes

FULL_SIZE = 60  # a signature with nonce R_MIN and a 32-byte s
TEST_BYTES = 1  # the judge grinds the test twin at one byte


def pin_dlog(index: int, size_bytes: int) -> int:
    """Appendix A.2: puzzle i accepts sighashes near 2^(256 - W + i), with W = 8 * bytes + 2."""
    return -(1 << (256 - (8 * size_bytes + 2) + index)) * R_MIN_INVERSE % ec.N


def assemble(rounds, pin_bytes, round_bytes, material) -> tuple[bytes, dict]:
    asm, puzzles, layout = Asm(), [], []
    # Pinning (Appendix A). The hardcoded SIGHASH_SINGLE signature verifies only when the bug fixes
    # the sighash, so every other SIGHASH_SINGLE signature on this input signs that constant too.
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
    # Nonce extraction (Appendix B), one block per round.
    left = 0  # commitments and signatures earlier rounds leave on the stack
    for r, (n, t) in enumerate(rounds):
        pool, commits = material["rounds"][r]["pool"], material["rounds"][r]["commits"]
        commit_at = [0] * n
        pool_at = [0] * n
        for j in reversed(range(n)):
            commit_at[j] = asm.push(commits[j])
        for j in reversed(range(n)):
            pool_at[j] = asm.push(pool[j][0])
        asm.op(S.OP_0)
        for i in range(t):
            asm.num(2 * n - i + 1 + left)       # the next index, from the witness
            asm.op(S.OP_ROLL)
            asm.num(n)                          # at most the deepest remaining signature
            asm.op(S.OP_MIN, S.OP_DUP)
            asm.num(n + 1 - i)                  # the same element's commitment
            asm.op(S.OP_ADD, S.OP_ROLL)
            asm.num(2 * n + t - 2 * i + 1 + left)  # the next preimage, from the witness
            asm.op(S.OP_ROLL, S.OP_HASH160, S.OP_EQUALVERIFY)
            asm.op(S.OP_ROLL)                   # the selected signature
        asm.num(2 * n + 1 + left)               # the puzzle signature
        asm.op(S.OP_ROLL, S.OP_SIZE)
        size_at = asm.num(FULL_SIZE - round_bytes[r])
        asm.op(S.OP_EQUALVERIFY)
        asm.num(t + 1)
        for _ in range(t):
            asm.num(2 * n + 2 + left)           # the deepest remaining key, from the witness
            asm.op(S.OP_ROLL)
        key_at = asm.push(ec.compressed(ec.mul(R_MIN_INVERSE)))
        asm.num(t + 1)
        asm.op(S.OP_CHECKMULTISIG if r == len(rounds) - 1 else S.OP_CHECKMULTISIGVERIFY)
        puzzles.append({"id": f"round{r}", "role": "round", "key_at": key_at, "size_at": size_at, "dlog": R_MIN_INVERSE})
        layout.append({"pool": pool_at, "commit": commit_at})
        left += 2 * (n - t)
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
        preimages = [specimen_bytes(f"round{r}|element{j}") for j in range(n)]
        material["rounds"].append({"pool": pool, "preimages": preimages, "commits": [hash160(p) for p in preimages]})

    locking, prod = assemble(rounds, pin_bytes, round_bytes, material)
    locking_test, test = assemble(rounds, TEST_BYTES, [TEST_BYTES] * len(rounds), material)

    # Unlocking script, bottom to top: the rounds' blocks, the last round deepest, then the four
    # pinning signatures with the first puzzle's on top.
    witness = []
    for r in reversed(range(len(rounds))):
        t = rounds[r][1]
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
