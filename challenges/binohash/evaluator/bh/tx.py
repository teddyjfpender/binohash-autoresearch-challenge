"""Legacy transactions and the legacy signature hash, including the SIGHASH_SINGLE bug."""
from __future__ import annotations

import dataclasses
import hashlib

from .script import strip_codeseparators

SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY = 1, 2, 3, 0x80
# What the legacy signature hash returns when SIGHASH_SINGLE names an output that does not
# exist: the 256-bit number one, serialised little-endian. ECDSA reads the 32 bytes big-endian.
SINGLE_BUG_DIGEST = b"\x01" + b"\x00" * 31


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


@dataclasses.dataclass
class TxIn:
    txid: bytes  # 32 bytes, as serialised
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF


@dataclasses.dataclass
class TxOut:
    value: int
    script: bytes


@dataclasses.dataclass
class Tx:
    version: int
    vin: list[TxIn]
    vout: list[TxOut]
    locktime: int

    def serialize(self) -> bytes:
        out = bytearray(self.version.to_bytes(4, "little") + varint(len(self.vin)))
        for txin in self.vin:
            out += txin.txid + txin.vout.to_bytes(4, "little") + varint(len(txin.script_sig)) + txin.script_sig
            out += txin.sequence.to_bytes(4, "little")
        out += varint(len(self.vout))
        for txout in self.vout:
            out += txout.value.to_bytes(8, "little") + varint(len(txout.script)) + txout.script
        return bytes(out + self.locktime.to_bytes(4, "little"))

    def copy(self) -> "Tx":
        return Tx(self.version, [dataclasses.replace(i) for i in self.vin],
                  [dataclasses.replace(o) for o in self.vout], self.locktime)


def sighash_preimage(tx: Tx, index: int, script_code: bytes, hashtype: int) -> bytes | None:
    """The bytes the legacy signature hash digests, or None where the SIGHASH_SINGLE bug applies.

    `script_code` is the script from the last executed OP_CODESEPARATOR with FindAndDelete
    already applied. `hashtype` is the signature's last byte; any value is consensus-valid.
    """
    base, anyone = hashtype & 0x1F, bool(hashtype & SIGHASH_ANYONECANPAY)
    if base == SIGHASH_SINGLE and index >= len(tx.vout):
        return None
    code = strip_codeseparators(script_code)
    out = bytearray(tx.version.to_bytes(4, "little"))
    inputs = [index] if anyone else range(len(tx.vin))
    out += varint(len(inputs))
    for i in inputs:
        txin = tx.vin[i]
        out += txin.txid + txin.vout.to_bytes(4, "little")
        out += (varint(len(code)) + code) if i == index else b"\x00"
        sequence = txin.sequence if i == index or base not in (SIGHASH_NONE, SIGHASH_SINGLE) else 0
        out += sequence.to_bytes(4, "little")
    if base == SIGHASH_NONE:
        out += b"\x00"
    elif base == SIGHASH_SINGLE:
        out += varint(index + 1)
        for i in range(index):
            out += (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + b"\x00"
        out += tx.vout[index].value.to_bytes(8, "little") + varint(len(tx.vout[index].script)) + tx.vout[index].script
    else:
        out += varint(len(tx.vout))
        for txout in tx.vout:
            out += txout.value.to_bytes(8, "little") + varint(len(txout.script)) + txout.script
    out += tx.locktime.to_bytes(4, "little") + hashtype.to_bytes(4, "little")
    return bytes(out)


def sighash(tx: Tx, index: int, script_code: bytes, hashtype: int) -> bytes:
    preimage = sighash_preimage(tx, index, script_code, hashtype)
    return SINGLE_BUG_DIGEST if preimage is None else sha256d(preimage)
