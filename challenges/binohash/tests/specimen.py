"""A small Binohash instance with switchable defects, for testing the evaluator.

It is independent of `builders/` on purpose: these tests are part of the contract and must not
change when submitted builder code does. Each fault removes one thing the security argument
needs; test_evaluator.py requires the evaluator to refuse every one of them.
"""
from __future__ import annotations

import hashlib
import json

from bh import script as S
from bh import secp256k1 as ec
from bh.interp import ripemd160
from bh.tx import SINGLE_BUG_DIGEST

Z_BUG = int.from_bytes(SINGLE_BUG_DIGEST, "big")
R_INV = pow(ec.R_MIN, -1, ec.N)


def _dummies(count):
    out = []
    for s in range(1, 128):
        for r in range(1, 128):
            key = ec.recover(r, s, Z_BUG) if ec.lift_x(r, False) else None
            if key:
                out.append((ec.der_encode(r, s, 3), ec.compressed(key)))
            if len(out) == count:
                return out
    raise ValueError


def _assemble(rounds, size, pin_w, faults, dummies, preimages):
    code, offsets = bytearray(), {"puzzles": [], "rounds": []}

    def push(data):
        at = len(code)
        code.extend(S.push(data))
        return at

    def num(value):
        at = len(code)
        code.extend(S.push_num(value))
        return at

    def op(*ops):
        code.extend(ops)

    if "if-branch" in faults:
        op(S.OP_1, S.OP_IF, S.OP_ENDIF)
    if "no-single-check" not in faults:
        push(dummies[0][0]), push(dummies[0][1]), op(S.OP_CHECKSIGVERIFY)
    for i in range(1, 5):
        index = 1 if "pin-keys-equal" in faults else i
        dlog = -(1 << (256 - pin_w + index)) * R_INV % ec.N
        op(S.OP_SIZE)
        size_at = num(size)
        op(S.OP_EQUALVERIFY)
        key_at = push(ec.compressed(ec.mul(dlog)))
        if "pin-unverified" in faults and i == 2:
            op(S.OP_CHECKSIG, S.OP_DROP)
        else:
            op(S.OP_CHECKSIGVERIFY)
        offsets["puzzles"].append((f"pin{i}", "pin", key_at, size_at, dlog))
    left, used = 0, 1
    for r, (n, t) in enumerate(rounds):
        pool = dummies[used:used + n]
        used += n
        if "pool-duplicate" in faults:
            pool[1] = pool[0]
        commits = [ripemd160(hashlib.sha256(p).digest()) for p in preimages[r]]
        if "commit-duplicate" in faults:
            commits[1] = commits[0]
        commit_at, pool_at = [0] * n, [0] * n
        if "pool-outside-scriptcode" not in faults:
            op(S.OP_CODESEPARATOR)
        for j in reversed(range(n)):
            commit_at[j] = push(commits[j])
        for j in reversed(range(n)):
            pool_at[j] = push(pool[j][0])
        if "pool-outside-scriptcode" in faults:
            op(S.OP_CODESEPARATOR)
        op(S.OP_0)
        for i in range(t):
            num(2 * n - i + 1 + left), op(S.OP_ROLL)
            if "no-clamp" not in faults:
                num(n), op(S.OP_MIN)
            op(S.OP_DUP), num(n + 1 - i), op(S.OP_ADD, S.OP_ROLL)
            num(2 * n + t - 2 * i + 1 + left), op(S.OP_ROLL, S.OP_HASH160)
            if "hash-unverified" in faults:
                op(S.OP_EQUAL, S.OP_DROP)
            else:
                op(S.OP_EQUALVERIFY)
            op(S.OP_ROLL)
        num(2 * n + 1 + left), op(S.OP_ROLL, S.OP_SIZE)
        size_at = num(size)
        if "size-unverified" in faults:
            op(S.OP_EQUAL, S.OP_DROP)
        else:
            op(S.OP_EQUALVERIFY)
        num(t + 1)
        for _ in range(t):
            num(2 * n + 2 + left), op(S.OP_ROLL)
        key_at = push(ec.compressed(ec.mul(R_INV)))
        if "spare-key" in faults:
            push(dummies[-1][1]), num(t + 2)
        else:
            num(t + 1)
        op(S.OP_CHECKMULTISIG if r == len(rounds) - 1 else S.OP_CHECKMULTISIGVERIFY)
        offsets["puzzles"].append((f"round{r}", "round", key_at, size_at, R_INV))
        offsets["rounds"].append((pool_at, commit_at, [k for _s, k in pool]))
        left += 2 * (n - t)
    return bytes(code), offsets


def build(rounds=((14, 3), (14, 3)), faults=()) -> bytes:
    """The instance file, as bytes, for `rounds` of (n, t) with the named faults."""
    faults = set(faults)
    dummies = _dummies(sum(n for n, _ in rounds) + 2)
    preimages = [[hashlib.sha256(f"specimen|{r}|{j}".encode()).digest()[:20] for j in range(n)]
                 for r, (n, _t) in enumerate(rounds)]
    if "preimage-is-key" in faults:
        preimages[0][1] = dummies[2][1]  # element 1 of round 0 is opened by its own public key
    locking, prod = _assemble(rounds, 55, 42, faults, dummies, preimages)
    locking_test, test = _assemble(rounds, 59, 10, faults, dummies, preimages)
    if "twin-differs" in faults:
        altered = bytearray(locking_test)
        altered[prod["rounds"][0][1][0] + 1] ^= 1  # one bit of a commitment
        locking_test = bytes(altered)
    witness = []
    for r in reversed(range(len(rounds))):
        t = rounds[r][1]
        witness.append({"puzzle": f"round{r}"})
        witness += [{"key": [r, i]} for i in range(t)]
        witness += [{"pre": [r, i]} for i in reversed(range(t))]
        witness += [{"index": [r, i], "enc": "rank", "add": i + 1} for i in reversed(range(t))]
    witness += [{"puzzle": f"pin{i}"} for i in (4, 3, 2, 1)]
    puzzles = []
    for (ident, role, key_at, size_at, dlog), other in zip(prod["puzzles"], test["puzzles"]):
        puzzles.append({"id": ident, "role": role, "key_at": key_at, "size_at": size_at,
                        "dlog": f"{(dlog + 1 if 'wrong-dlog' in faults and ident == 'pin3' else dlog):064x}",
                        "dlog_test": f"{other[4]:064x}"})
    instance = {
        "schema": "bh-instance-v1", "locking": locking.hex(), "locking_test": locking_test.hex(),
        "puzzles": puzzles,
        "rounds": [{"puzzle": f"round{r}", "t": t, "pool": prod["rounds"][r][0], "commit": prod["rounds"][r][1],
                    "keys": [k.hex() for k in prod["rounds"][r][2]], "preimages": [p.hex() for p in preimages[r]]}
                   for r, (_n, t) in enumerate(rounds)],
        "witness": witness,
    }
    return json.dumps(instance, sort_keys=True).encode()
