import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

from bac import ledger  # noqa: E402
from bac.common import ContractError  # noqa: E402

KEY = bytes(range(32))
TRACKS = {
    "standard": {"name": "standard", "spec": "bh1-standard", "standard": {"floorBits": "81.7"}},
    "high": {"name": "high", "spec": "bh1-high", "standard": {"floorBits": "88.4"}},
}
ARCHS = {"a": {}, "b": {}}


def row(size, opcodes, work, arch="a", track="standard", instance="1", when=100, security="81.740"):
    work = f"{work:.3f}"
    return {
        "unix_time": str(when), "track": track, "spec": TRACKS[track]["spec"], "architecture": arch,
        "bytes": str(size), "opcodes": str(opcodes), "work_bits": work, "score": ledger.score_of(size, opcodes, work),
        "security_bits": security, "lanes": "48", "engine": "reference-48+core-20", "seed": "ab" * 32,
        "instance_sha256": instance.rjust(64, "0"), "verifier_sha256": "12" * 32, "commit": "abc1234", "pr": "",
        "author": "someone", "model": "m", "harness": "h", "submission": "standard/x-instance", "kind": "historical",
        "standing": "", "status": "OK", "note": "n", "mac": ledger.UNSIGNED,
    }


class LedgerTest(unittest.TestCase):
    def test_seed_is_keyed_and_bound_to_the_instance(self):
        a = ledger.derive_seed(KEY, "aa" * 32)
        self.assertRegex(a, r"^[0-9a-f]{64}$")
        self.assertNotEqual(a, ledger.derive_seed(KEY, "ab" * 32))
        self.assertNotEqual(a, ledger.derive_seed(bytes(32), "aa" * 32))
        with self.assertRaises(ContractError):
            ledger.derive_seed(KEY, "short")

    def test_score_is_exact_and_in_units_of_two_to_the_forty(self):
        self.assertEqual(ledger.score_of(9349, 199, "40.000"), "1860451.000")
        self.assertEqual(ledger.score_of(9349, 199, "41.000"), "3720902.000")
        self.assertEqual(ledger.score_of(1000, 100, "39.000"), "50000.000")
        self.assertEqual(ledger.score_of(9349, 199, "46.990"), "236492790.557")

    def test_round_trip_and_chain(self):
        rows = [row(9000, 199, 47, instance="1"), row(8000, 199, 47, instance="2", when=200), row(8000, 180, 48, instance="3", when=300)]
        ledger.sign(KEY, rows)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "results.tsv"
            ledger.write(path, rows)
            self.assertEqual(ledger.read(path), rows)
        self.assertEqual(ledger.verify_chain(KEY, rows), [])
        self.assertEqual(ledger.check_rows(rows, TRACKS, ARCHS, signed=True), [])
        for tamper in (
            lambda r: r[1].__setitem__("opcodes", "150"),
            lambda r: r[1].__setitem__("security_bits", "99.000"),
            lambda r: r.pop(1),
            lambda r: r.reverse(),
            lambda r: r.insert(1, dict(r[0])),
        ):
            copy = [dict(r) for r in rows]
            tamper(copy)
            self.assertTrue(ledger.verify_chain(KEY, copy))
        self.assertTrue(ledger.verify_chain(bytes(32), rows))

    def test_static_checks(self):
        good = [row(9000, 199, 47)]
        ledger.sign(KEY, good)
        bad = [
            {**good[0], "score": "1000.001"},
            {**good[0], "architecture": "zzz"},
            {**good[0], "track": "high"},
            {**good[0], "security_bits": "81.699"},
            {**good[0], "instance_sha256": "xyz"},
            {**good[0], "work_bits": "many"},
            {**good[0], "status": "FAIL"},
            {**good[0], "standing": "best"},
            {**good[0], "mac": ledger.UNSIGNED},
        ]
        for r in bad:
            self.assertTrue(ledger.check_rows([r], TRACKS, ARCHS, signed=True), r)
        self.assertTrue(ledger.check_rows([good[0], good[0]], TRACKS, ARCHS, signed=True))
        self.assertTrue(ledger.check_rows([row(1, 1, 1, when=5, instance="2"), row(1, 1, 1, when=4, instance="3")], TRACKS, ARCHS, signed=False))

    def test_standing(self):
        rows = [row(9000, 199, 47, "a", instance="1"), row(9500, 150, 48, "a", instance="2")]
        bips = 100
        new = lambda *a, **k: row(*a, instance="9", **k)  # noqa: E731
        # The first instance of an architecture is always recorded.
        self.assertEqual(ledger.standing(rows, new(20000, 201, 60, "b"), bips)[0], ["new-architecture"])
        # Beats the architecture's best score and needs less work than everything it does not undercut.
        self.assertEqual(ledger.standing(rows, new(9000, 199, 46, "a"), bips)[0], ["architecture-elite", "front"])
        # Advances the front without beating the elite score: fewer opcodes than anything recorded.
        self.assertEqual(ledger.standing(rows, new(9900, 140, 50, "a"), bips)[0], ["front"])
        # Smaller than anything recorded: on the front whatever its work.
        self.assertEqual(ledger.standing(rows, new(8999, 201, 55, "a"), bips)[0], ["front"])
        # Inside the margin: neither.
        standings, reason = ledger.standing(rows, new(9000, 199, 46.99, "a"), bips)
        self.assertEqual(standings, [])
        self.assertIn("neither", reason)
        # Dominated on all three.
        self.assertEqual(ledger.standing(rows, new(9600, 199, 48, "a"), bips)[0], [])
        # The same instance again.
        self.assertIn("already", ledger.standing(rows, row(1, 1, 1, "a", instance="1"), bips)[1])
        # Tracks are separate boards.
        self.assertEqual(ledger.standing(rows, new(20000, 201, 60, "a", track="high", security="88.413"), bips)[0],
                         ["new-architecture", "front"])

    def test_row_from_score(self):
        score = {
            "status": "OK", "spec": "bh1-standard", "seed": "ab" * 32, "engine": "reference-48+core-20",
            "digests": {"instance": "cd" * 32}, "checks": {"lanes": 48},
            "metrics": {"bytes": 9349, "opcodes": 199, "work_bits": "46.990032", "security_bits": "81.739721"},
        }
        common = dict(track=TRACKS["standard"], architecture="a", seed="ab" * 32, verifier="12" * 32, unix_time=5,
                      commit="c", pr="7", author="x", model="m", harness="h", submission="standard/y", kind="submission", note="t")
        made = ledger.row_from_score(score, **common)
        self.assertEqual((made["bytes"], made["opcodes"], made["work_bits"], made["security_bits"], made["lanes"]),
                         ("9349", "199", "46.990", "81.740", "48"))
        self.assertEqual(made["score"], ledger.score_of(9349, 199, "46.990"))
        self.assertEqual(ledger.check_rows([made], TRACKS, ARCHS, signed=False), [])
        for broken in (
            {**score, "status": "REJECTED"},
            {**score, "spec": "bh1-high"},
            {**score, "seed": "00" * 32},
            {**score, "metrics": {**score["metrics"], "security_bits": "81.699999"}},
        ):
            with self.assertRaises(ContractError):
                ledger.row_from_score(broken, **common)


if __name__ == "__main__":
    unittest.main()
