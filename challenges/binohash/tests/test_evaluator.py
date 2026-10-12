"""The judge accepts a sound small instance and refuses every seeded defect.

Each fault in specimen.py removes one thing the security argument needs. A defect the judge does
not refuse would let a cheaper, unsound instance onto the board, so these are the tests that
matter most. They use a two-round 14-choose-3 instance to stay fast.
"""
import json
import pathlib
import unittest

import specimen
import support  # noqa: F401
from bh.instance import Reject
from bh.judge import Judge

SPEC = json.loads((pathlib.Path(__file__).resolve().parents[1] / "specs" / "bh1-standard.json").read_text())
SEED = bytes(range(32))

REFUSED = {
    "no-clamp": "soundness",                # an index that can reach another round's signatures
    "hash-unverified": "structure",         # a commitment compared but never enforced
    "size-unverified": "structure",         # a puzzle whose size is compared but never enforced
    "pin-unverified": "soundness",          # a pinning signature whose verification is dropped
    "spare-key": "structure",               # a multisig the puzzle key need not take part in
    "no-single-check": "single-bug",        # SIGHASH_SINGLE usable for pinning
    "pin-keys-equal": "pin-cover",          # two pinning puzzles one sighash mode can serve
    "pool-duplicate": "nonce-space",        # fewer distinct selections than claimed
    "pool-outside-scriptcode": "nonce-space",  # selections that do not change the sighash
    "commit-duplicate": "binding",          # one preimage opens two elements
    "wrong-dlog": "puzzle-key",             # a puzzle key the claimed work does not follow from
    "twin-differs": "twin",                 # a test script that is not the production script
    "if-branch": "straight-line",           # control flow the audit does not cover
}


def judge(raw: bytes, lanes: int = 2, audit: int = 1, seed: bytes = SEED) -> Judge:
    run = Judge(raw, SPEC | {"floorBits": "0"}, seed)
    run.run(lanes, audit, 1)
    return run


class Sound(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = specimen.build()
        cls.judged = judge(cls.raw)

    def test_counts(self):
        metrics = self.judged.metrics
        self.assertEqual(metrics["opcodes"], 13 + 2 * (11 * 3 + 5) + 2)  # two OP_CODESEPARATORs
        self.assertEqual(metrics["bytes"], metrics["locking_bytes"] + metrics["unlocking_bytes"])
        self.assertEqual(self.judged.counts["honest_spends"], 2)
        self.assertGreater(self.judged.counts["mutants"], 1000)
        self.assertEqual(self.judged.counts["table_entries"], 28)

    def test_counts_do_not_depend_on_the_seed(self):
        other = judge(self.raw, seed=bytes(reversed(range(32))))
        self.assertEqual(other.metrics, self.judged.metrics)

    def test_floor_is_enforced(self):
        with self.assertRaises(Reject) as caught:
            Judge(self.raw, SPEC | {"floorBits": "200"}, SEED).run(1, 0, 0)
        self.assertEqual(caught.exception.stage, "security-floor")

    def test_single_round(self):
        self.assertEqual(len(judge(specimen.build(rounds=((16, 4),))).metrics["rounds"]), 1)


class Defects(unittest.TestCase):
    def test_every_defect_is_refused_for_its_reason(self):
        for fault, stage in REFUSED.items():
            with self.subTest(fault=fault):
                with self.assertRaises(Reject) as caught:
                    judge(specimen.build(faults=(fault,)))
                self.assertEqual(caught.exception.stage, stage, caught.exception.reason)


class Format(unittest.TestCase):
    def reject(self, mutate) -> str:
        data = json.loads(specimen.build())
        mutate(data)
        with self.assertRaises(Reject) as caught:
            judge(json.dumps(data).encode(), lanes=1, audit=0)
        return caught.exception.stage

    def test_unknown_and_missing_fields(self):
        self.assertEqual(self.reject(lambda d: d.update(claimed_bits=128)), "format")
        self.assertEqual(self.reject(lambda d: d.pop("witness")), "format")
        self.assertEqual(self.reject(lambda d: d["rounds"][0].update(t=True)), "format")
        self.assertEqual(self.reject(lambda d: d["puzzles"][0].update(dlog="zz")), "format")

    def test_not_json(self):
        with self.assertRaises(Reject):
            Judge(b"\xff\xfe", SPEC, SEED)
        with self.assertRaises(Reject):
            Judge(b"[" * 100000, SPEC, SEED)

    def test_declared_structure_must_match_the_script(self):
        self.assertEqual(self.reject(lambda d: d["rounds"][0]["pool"].__setitem__(0, d["rounds"][0]["pool"][0] + 1)), "structure")
        self.assertIn(self.reject(lambda d: d["rounds"][0]["preimages"].__setitem__(5, "00" * 20)), ("binding", "honest-spend"))
        self.assertEqual(self.reject(lambda d: d["rounds"][0]["keys"].__setitem__(5, d["rounds"][0]["keys"][4])), "nonce-space")
        self.assertEqual(self.reject(lambda d: d["rounds"][0].update(t=2)), "format")
        self.assertEqual(self.reject(lambda d: d["witness"].reverse()), "honest-spend")

    def test_a_pool_smaller_than_declared(self):
        def shrink(d):
            for name in ("pool", "commit", "keys", "preimages"):
                d["rounds"][1][name] = d["rounds"][1][name][:-1]
        # The script still holds fourteen signatures. The spender, who knows every preimage, could
        # select the undeclared one, so the real selection space is larger than the counted one.
        self.assertEqual(self.reject(shrink), "nonce-space")


if __name__ == "__main__":
    unittest.main()
