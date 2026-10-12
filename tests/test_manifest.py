import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

from bac import manifest, rules_binohash  # noqa: E402
from bac.common import Challenge, ContractError  # noqa: E402


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.challenge = Challenge("binohash")
        self.architectures = self.challenge.architectures()
        self.good = {
            "schema": "bac-submission-v1", "challenge": "binohash", "track": "standard", "architecture": "rolled-subset",
            "title": "A title", "build": {"BINO_BUILDER": "paper", "BINO_ROUNDS": "126:8,126:8", "BINO_ROUND_BYTES": "5,5"},
            "authors": ["octocat"], "model": "Some Model 1.0", "harness": "Some Harness",
        }

    def check(self, data, track="standard", submission_id="my-instance"):
        return manifest.validate(self.challenge, track, submission_id, data, self.architectures)

    def test_good(self):
        checked = self.check(self.good)
        self.assertEqual(checked["id"], "my-instance")
        self.assertEqual(checked["parents"], [])
        self.assertEqual(self.check({**self.good, "claimed": {"bytes": 9000, "opcodes": 180, "work_bits": 44.5}})["claimed"]["opcodes"], 180)

    def test_rejections(self):
        bad = [
            {**self.good, "track": "high"},
            {**self.good, "architecture": "not-registered"},
            {**self.good, "build": {"PATH": "/tmp"}},
            {**self.good, "build": {"BINO_SPEC": "bh1-high"}},
            {**self.good, "build": {"BINO_STAGE": "build"}},
            {**self.good, "build": {"BINO_OUT": "/tmp"}},
            {**self.good, "build": {"BAC_LEDGER_KEY": "00"}},
            {**self.good, "build": {"BINO_ROUNDS": "a b; rm -rf /"}},
            {**self.good, "build": {"BINO_ROUNDS": "$(id)"}},
            {**self.good, "authors": []},
            {**self.good, "authors": ["not a login"]},
            {**self.good, "title": "tab\there"},
            {**self.good, "model": ""},
            {**self.good, "claimed": {"bytes": -1}},
            {**self.good, "claimed": {"security_bits": 128}},
            {**self.good, "extra": 1},
            {**self.good, "parents": ["Bad Id"]},
            {**self.good, "discussion": "https://example.com/x"},
            {k: v for k, v in self.good.items() if k != "harness"},
            [],
        ]
        for data in bad:
            with self.assertRaises(ContractError, msg=data):
                self.check(data)
        with self.assertRaises(ContractError):
            self.check(self.good, submission_id="Bad_Id")
        with self.assertRaises(ContractError):
            self.check(self.good, track="nosuch")

    def test_shipped_builders_are_classified(self):
        self.assertEqual(rules_binohash.architecture_of({}), "rolled-subset")
        self.assertEqual(rules_binohash.architecture_of({"BINO_BUILDER": "paper", "BINO_ROUNDS": "90:10"}), "rolled-subset")
        self.assertIsNone(rules_binohash.architecture_of({"BINO_BUILDER": "something-new"}))
        self.assertEqual(manifest.classified(self.challenge, self.check(self.good)), "rolled-subset")

    def test_new_creates_a_template_that_must_be_filled_in(self):
        import contextlib, io, shutil
        from bac import cli
        directory = self.challenge.dir / "submissions" / "standard" / "zz-template-test"
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["new", "binohash", "standard", "zz-template-test", "--architecture", "rolled-subset"]), 0)
            self.assertTrue((directory / "NOTES.md").is_file())
            with self.assertRaises(ContractError):
                manifest.load(self.challenge, directory)  # placeholders and short notes
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_recorded_manifests_are_valid(self):
        root = self.challenge.dir / "submissions"
        found = sorted(p for p in root.glob("*/*") if p.is_dir())
        self.assertGreaterEqual(len(found), 2)
        for directory in found:
            checked = manifest.load(self.challenge, directory)
            # The rules know the shipped builders. A builder they do not know classifies as None;
            # its architecture was a maintainer's approval, which no rule can check.
            self.assertIn(manifest.classified(self.challenge, checked), (checked["architecture"], None))


if __name__ == "__main__":
    unittest.main()
