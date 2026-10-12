"""The reference engine against fixed expectations and against spends Bitcoin Core has judged."""
import pathlib
import unittest

import support  # noqa: F401
from bh import script as S
from bh import secp256k1 as ec
from bh.interp import Trace, verify
from bh.tx import SINGLE_BUG_DIGEST, Tx, TxIn, TxOut, sighash

DATA = pathlib.Path(__file__).resolve().parent / "data"


def parse_tx(raw: bytes) -> Tx:
    pos = 0

    def take(n):
        nonlocal pos
        out = raw[pos:pos + n]
        pos += n
        return out

    def varint():
        first = take(1)[0]
        return first if first < 0xFD else int.from_bytes(take({0xFD: 2, 0xFE: 4, 0xFF: 8}[first]), "little")

    version = int.from_bytes(take(4), "little")
    vin = []
    for _ in range(varint()):
        txid, vout = take(32), int.from_bytes(take(4), "little")
        script = take(varint())
        vin.append(TxIn(txid, vout, script, int.from_bytes(take(4), "little")))
    vout = []
    for _ in range(varint()):
        value = int.from_bytes(take(8), "little")
        vout.append(TxOut(value, take(varint())))
    tx = Tx(version, vin, vout, int.from_bytes(take(4), "little"))
    assert pos == len(raw) and tx.serialize() == raw
    return tx


class FindAndDelete(unittest.TestCase):
    def test_removes_only_at_operation_boundaries(self):
        sig = bytes.fromhex("300602010102010103")
        needle = S.push(sig)
        embedded = S.push(b"\xaa" + needle + b"\xbb")  # the same bytes inside a larger push
        script = needle + embedded + bytes([S.OP_DUP]) + needle + needle + bytes([S.OP_CHECKSIG])
        self.assertEqual(S.find_and_delete(script, needle), embedded + bytes([S.OP_DUP, S.OP_CHECKSIG]))

    def test_absent_needle_and_truncated_tail(self):
        script = bytes([S.OP_DUP, 0x05, 0x01, 0x02])  # a push that runs past the end
        self.assertEqual(S.find_and_delete(script, S.push(b"\x09")), script)
        self.assertEqual(S.find_and_delete(bytes([0x01, 0x09]) + script, S.push(b"\x09")), script)

    def test_codeseparators_are_not_serialised(self):
        script = bytes([S.OP_DUP, S.OP_CODESEPARATOR]) + S.push(bytes([S.OP_CODESEPARATOR])) + bytes([S.OP_CODESEPARATOR, S.OP_NIP])
        self.assertEqual(S.strip_codeseparators(script), bytes([S.OP_DUP]) + S.push(bytes([S.OP_CODESEPARATOR])) + bytes([S.OP_NIP]))


class Numbers(unittest.TestCase):
    def test_round_trip_and_shortest_push(self):
        for value in (0, 1, -1, 16, 17, 127, 128, 255, 256, -127, -128, -255, 32767, 32768, 2 ** 31 - 1, -(2 ** 31 - 1)):
            self.assertEqual(S.num_decode(S.num_encode(value)), value)
        self.assertEqual(S.push_num(0), b"\x00")
        self.assertEqual(S.push_num(16), bytes([S.OP_16]))
        self.assertEqual(S.push_num(55), b"\x01\x37")
        self.assertEqual(S.push_num(241), b"\x02\xf1\x00")
        with self.assertRaises(S.ScriptError):
            S.num_decode(b"\x00" * 5)

    def test_non_minimal_numbers_are_consensus_valid(self):
        self.assertEqual(S.num_decode(b"\x05\x00\x00"), 5)
        self.assertEqual(S.num_decode(b"\x00\x80"), 0)


class SigHash(unittest.TestCase):
    def tx(self, outputs):
        vin = [TxIn(bytes([i]) * 32, i) for i in range(3)]
        return Tx(2, vin, [TxOut(0, b"\x6a")] * outputs, 7)

    def test_single_bug_digest(self):
        code = bytes([S.OP_CHECKSIG])
        self.assertEqual(sighash(self.tx(1), 1, code, 0x03), SINGLE_BUG_DIGEST)
        self.assertEqual(sighash(self.tx(1), 1, code, 0x83), SINGLE_BUG_DIGEST)
        self.assertNotEqual(sighash(self.tx(2), 1, code, 0x03), SINGLE_BUG_DIGEST)
        self.assertNotEqual(sighash(self.tx(1), 1, code, 0x01), SINGLE_BUG_DIGEST)

    def test_every_hash_type_byte_gives_its_own_digest(self):
        code = bytes([S.OP_CHECKSIG])
        digests = {sighash(self.tx(3), 1, code, flag) for flag in range(256)}
        self.assertEqual(len(digests), 256)

    def test_modes_commit_to_what_they_should(self):
        code, tx = bytes([S.OP_CHECKSIG]), self.tx(1)
        other = tx.copy()
        other.vout[0] = TxOut(1, b"\x6a")
        for flag, moved in ((0x01, True), (0x81, True), (0x02, False), (0x82, False)):
            self.assertEqual(sighash(tx, 1, code, flag) != sighash(other, 1, code, flag), moved, hex(flag))
        other = tx.copy()
        other.vin[2].sequence = 5
        for flag, moved in ((0x01, True), (0x81, False), (0x02, False), (0x82, False)):
            self.assertEqual(sighash(tx, 1, code, flag) != sighash(other, 1, code, flag), moved, hex(flag))
        other = tx.copy()
        other.vin[2].txid = b"\x09" * 32
        for flag, moved in ((0x01, True), (0x81, False), (0x02, True), (0x82, False)):
            self.assertEqual(sighash(tx, 1, code, flag) != sighash(other, 1, code, flag), moved, hex(flag))


class Limits(unittest.TestCase):
    def run_script(self, locking: bytes, unlocking: bytes = b""):
        trace = Trace()
        tx = Tx(2, [TxIn(b"\x01" * 32, 0), TxIn(b"\x02" * 32, 0)], [TxOut(0, b"\x6a")], 0)
        return verify(unlocking, locking, tx, 1, trace=trace), trace

    def test_operation_limit_counts_multisig_keys(self):
        ok, trace = self.run_script(bytes([S.OP_1]) + bytes([S.OP_NOP]) * 201)
        self.assertTrue(ok)
        self.assertEqual(trace.ops, 201)
        self.assertFalse(self.run_script(bytes([S.OP_1]) + bytes([S.OP_NOP]) * 202)[0])
        key = S.push(ec.compressed(ec.G))
        multisig = bytes([S.OP_0, S.OP_0]) + key * 3 + bytes([S.OP_1 + 2, S.OP_CHECKMULTISIG])  # 0-of-3
        ok, trace = self.run_script(multisig)
        self.assertTrue(ok)
        self.assertEqual(trace.ops, 1 + 3)
        self.assertTrue(self.run_script(bytes([S.OP_NOP]) * 197 + multisig)[0])
        self.assertFalse(self.run_script(bytes([S.OP_NOP]) * 198 + multisig)[0])

    def test_stack_and_element_limits(self):
        self.assertTrue(self.run_script(bytes([S.OP_1]) * 1000)[0])
        self.assertFalse(self.run_script(bytes([S.OP_1]) * 1001)[0])
        self.assertTrue(self.run_script(S.push(b"\x01" * 520))[0])
        self.assertFalse(self.run_script(S.push(b"\x01" * 521))[0])

    def test_disabled_opcodes_fail_even_when_not_executed(self):
        self.assertFalse(self.run_script(bytes([S.OP_1, S.OP_0, S.OP_IF, S.OP_CAT, S.OP_ENDIF]))[0])
        self.assertTrue(self.run_script(bytes([S.OP_1, S.OP_0, S.OP_IF, S.OP_RETURN, S.OP_ENDIF]))[0])

    def test_null_dummy_and_strict_der(self):
        key = S.push(ec.compressed(ec.G))
        self.assertFalse(self.run_script(bytes([S.OP_1, S.OP_0]) + key + bytes([S.OP_1, S.OP_CHECKMULTISIG, S.OP_NOT]))[0])
        loose = S.push(bytes.fromhex("30070201010202000103"))  # s carries a needless leading zero
        ok, trace = self.run_script(loose + key + bytes([S.OP_CHECKSIG, S.OP_NOT]))
        self.assertFalse(ok)
        self.assertIn("strict DER", trace.error)


class CoreVectors(unittest.TestCase):
    """Spends whose verdicts Bitcoin Core's consensus library reached (tools/core). The reference
    engine must reach the same ones; CI replays the same file through Core again."""

    def test_reference_engine_reaches_cores_verdicts(self):
        lines = (DATA / "core-vectors.txt").read_text(encoding="utf-8").splitlines()
        self.assertGreater(len(lines), 10)
        valid = 0
        for line in lines:
            name, locking, spend, index, expected = line.split()
            tx = parse_tx(bytes.fromhex(spend))
            unlocking = tx.vin[int(index)].script_sig
            tx.vin[int(index)].script_sig = b""
            self.assertEqual(verify(unlocking, bytes.fromhex(locking), tx, int(index)), expected == "1", name)
            valid += expected == "1"
        self.assertGreater(valid, 4)


if __name__ == "__main__":
    unittest.main()
