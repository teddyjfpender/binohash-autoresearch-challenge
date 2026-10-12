"""Shared parts for builders: a script assembler and the pieces every Binohash instance needs."""
from __future__ import annotations

import hashlib

from bh import script as S
from bh import secp256k1 as ec
from bh.interp import ripemd160
from bh.tx import SINGLE_BUG_DIGEST

Z_BUG = int.from_bytes(SINGLE_BUG_DIGEST, "big")
R_MIN_INVERSE = pow(ec.R_MIN, -1, ec.N)
SIGHASH_SINGLE = 0x03


class Asm:
    """Appends operations and remembers where each push starts."""

    def __init__(self):
        self.code = bytearray()

    def op(self, *opcodes: int) -> "Asm":
        self.code += bytes(opcodes)
        return self

    def push(self, data: bytes) -> int:
        offset = len(self.code)
        self.code += S.push(data)
        return offset

    def num(self, value: int) -> int:
        offset = len(self.code)
        self.code += S.push_num(value)
        return offset


def hash160(data: bytes) -> bytes:
    return ripemd160(hashlib.sha256(data).digest())


def specimen_bytes(label: str, length: int = 20) -> bytes:
    """Public, reproducible stand-ins for the secrets of a real instance."""
    return hashlib.sha256(b"binohash-specimen|" + label.encode()).digest()[:length]


def dummy_signatures(count: int, skip: int = 0) -> list[tuple[bytes, bytes]]:
    """`count` distinct 9-byte SIGHASH_SINGLE signatures with the key each one verifies under when
    the SIGHASH_SINGLE bug fixes the sighash (Binohash sections 2.3 and 2.4.3)."""
    out, seen = [], 0
    for s in range(1, 128):
        for r in range(1, 128):
            if ec.lift_x(r, False) is None:
                continue
            seen += 1
            if seen <= skip:
                continue
            key = ec.recover(r, s, Z_BUG)
            if key is None:
                continue
            out.append((ec.der_encode(r, s, SIGHASH_SINGLE), ec.compressed(key)))
            if len(out) == count:
                return out
    raise ValueError("not enough 9-byte signatures")


def knob_ints(knobs: dict, name: str, default: str) -> list[int]:
    return [int(part) for part in knobs.get(name, default).replace(":", ",").split(",")]
