"""Re-validation of a recorded row against a fresh evaluation (`challenge.py compare-row`)."""
import argparse
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from bac import cli, ledger, verifier  # noqa: E402

ROW = {
    "unix_time": "100", "track": "standard", "spec": "bh1-standard", "architecture": "rolled-subset",
    "bytes": "9349", "opcodes": "199", "work_bits": "46.990", "score": ledger.score_of(9349, 199, "46.990"),
    "security_bits": "81.740", "lanes": "48", "engine": "reference-48+core-20", "seed": "ab" * 32,
    "instance_sha256": "cd" * 32, "verifier_sha256": "12" * 32, "commit": "genesis", "pr": "", "author": "someone",
    "model": "m", "harness": "h", "submission": "standard/paper-two-round", "kind": "historical", "standing": "",
    "status": "OK", "note": "n", "mac": ledger.UNSIGNED,
}


class CompareRowTest(unittest.TestCase):
    def compare(self, same_verifier=False, seed=ROW["seed"], **changes):
        score = {
            "status": "OK", "spec": "bh1-standard", "seed": seed, "engine": "reference-48+core-20",
            "digests": {"instance": ROW["instance_sha256"]}, "checks": {"lanes": 48},
            "metrics": {"bytes": 9349, "opcodes": 199, "work_bits": "46.990032", "security_bits": "81.739721", **changes},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "score.json"
            path.write_text(json.dumps(score))
            args = argparse.Namespace(challenge="binohash", submission=ROW["submission"], score=str(path), seed=seed,
                                      same_verifier=same_verifier)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), patch.object(ledger, "read", return_value=[dict(ROW)]):
                code = cli.cmd_compare_row(args)
        return code, out.getvalue()

    def test_a_row_reproduces_under_the_evaluator_that_recorded_it(self):
        with patch.object(verifier, "digest", return_value=ROW["verifier_sha256"]):
            code, out = self.compare(same_verifier=True)
        self.assertEqual(code, 0, out)
        self.assertNotIn("note", out)

    def test_a_later_evaluator_is_reported_and_is_not_a_failure(self):
        with patch.object(verifier, "digest", return_value="f" * 64):
            code, out = self.compare()
            strict, _ = self.compare(same_verifier=True)
        self.assertEqual(code, 0, out)
        self.assertIn("note verifier_sha256", out)
        self.assertEqual(strict, 1)

    def test_a_different_count_fails_whatever_the_evaluator(self):
        with patch.object(verifier, "digest", return_value="f" * 64):
            code, out = self.compare(opcodes=198)
            self.assertEqual(code, 1)
            self.assertIn("FAIL opcodes", out)
            code, out = self.compare(work_bits="46.5")
            self.assertEqual(code, 1)
            self.assertIn("FAIL work_bits", out)

    def test_a_different_seed_fails(self):
        with patch.object(verifier, "digest", return_value="f" * 64):
            code, out = self.compare(seed="00" * 32)
        self.assertEqual(code, 1)
        self.assertIn("FAIL seed", out)


if __name__ == "__main__":
    unittest.main()
