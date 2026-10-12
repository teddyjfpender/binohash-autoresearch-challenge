"""End-to-end intake on a scratch git repository: policy plus manifest, read from git objects."""
import contextlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from bac import cli  # noqa: E402

B = "challenges/binohash"
MANIFEST = {
    "schema": "bac-submission-v1", "challenge": "binohash", "track": "standard", "architecture": "rolled-subset",
    "title": "Test instance", "build": {"BINO_BUILDER": "paper", "BINO_ROUNDS": "126:8,126:8"},
    "authors": ["octocat"], "model": "none", "harness": "none",
}


class IntakeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        (self.repo / B / "builders").mkdir(parents=True)
        (self.repo / B / "evaluator/bh").mkdir(parents=True)
        shutil.copy(ROOT / B / "architectures.json", self.repo / B / "architectures.json")
        (self.repo / B / "builders/paper.py").write_text("# builder\n")
        (self.repo / B / "evaluator/bh/judge.py").write_text("# trusted\n")
        self.git("init", "-q", "-b", "main")
        self.base = self.commit("base")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                              check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def submit(self, manifest=MANIFEST, notes="n" * 2048, directory="standard/test-instance"):
        target = self.repo / B / "submissions" / directory
        target.mkdir(parents=True)
        (target / "submission.json").write_text(json.dumps(manifest))
        (target / "NOTES.md").write_text(notes)

    def intake(self, head):
        out = self.tmp / "out"
        shutil.rmtree(out, ignore_errors=True)
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["intake", "--repo", str(self.repo), "--base", self.base, "--head", head, "--out", str(out)])
        self.assertEqual(code, 0)
        policy = json.loads((out / "policy.json").read_text())
        manifest = json.loads((out / "manifest.json").read_text()) if (out / "manifest.json").exists() else None
        return policy, manifest

    def test_valid_submission_with_code(self):
        self.submit()
        (self.repo / B / "builders/paper.py").write_text("# builder, changed\nimport hashlib\n")
        policy, manifest = self.intake(self.commit("submission"))
        self.assertTrue(policy["ok"], policy["errors"])
        self.assertEqual((manifest["track"], manifest["id"], manifest["architecture"]), ("standard", "test-instance", "rolled-subset"))
        self.assertEqual(policy["classified"], "rolled-subset")

    def test_trusted_change_is_refused(self):
        self.submit()
        (self.repo / B / "evaluator/bh/judge.py").write_text("# tampered\n")
        policy, manifest = self.intake(self.commit("tamper"))
        self.assertFalse(policy["ok"])
        self.assertIsNone(manifest)

    def test_bad_manifest_and_short_notes(self):
        self.submit(manifest={**MANIFEST, "build": {"LD_PRELOAD": "x"}})
        policy, manifest = self.intake(self.commit("bad knob"))
        self.assertFalse(policy["ok"])
        self.assertIsNone(manifest)
        self.git("reset", "-q", "--hard", self.base)
        self.submit(notes="too short")
        policy, manifest = self.intake(self.commit("short notes"))
        self.assertFalse(policy["ok"])

    def test_new_architecture(self):
        registry = json.loads((self.repo / B / "architectures.json").read_text())
        registry["architectures"].append({"id": "brand-new", "name": "Brand new", "mechanism": "m" * 220,
                                          "distinguishing": "d" * 120, "references": []})
        (self.repo / B / "architectures.json").write_text(json.dumps(registry, indent=1) + "\n")
        # A new architecture comes with a new builder, which the rules cannot classify.
        self.submit(manifest={**MANIFEST, "architecture": "brand-new", "build": {"BINO_BUILDER": "paired"}})
        policy, manifest = self.intake(self.commit("new architecture"))
        self.assertTrue(policy["ok"], policy["errors"])
        self.assertTrue(policy["proposes_architecture"])
        self.assertIsNone(policy["classified"])
        self.assertEqual(manifest["architecture"], "brand-new")

    def test_declared_architecture_must_match_the_build_knobs(self):
        registry = json.loads((self.repo / B / "architectures.json").read_text())
        registry["architectures"].append({"id": "brand-new", "name": "Brand new", "mechanism": "m" * 220,
                                          "distinguishing": "d" * 120, "references": []})
        (self.repo / B / "architectures.json").write_text(json.dumps(registry, indent=1) + "\n")
        # The shipped builder under a new architecture's name.
        self.submit(manifest={**MANIFEST, "architecture": "brand-new"})
        policy, manifest = self.intake(self.commit("misfiled"))
        self.assertFalse(policy["ok"])
        self.assertIsNone(manifest)
        self.assertIn("rolled-subset", " ".join(policy["errors"]))

    def test_source_gate(self):
        for name, body in (
            ("a.py", "import os\n"),
            ("b.py", "import subprocess\nsubprocess.run(['id'])\n"),
            ("c.py", "data = open('/etc/passwd').read()\n"),
            ("d.py", "x = ().__class__.__mro__\n"),
            ("blob.bin", "x"),
            ("helper.sh", "#!/bin/sh\n"),
        ):
            self.git("reset", "-q", "--hard", self.base)
            self.git("clean", "-qfd")
            self.submit()
            (self.repo / B / "builders" / name).write_text(body)
            policy, _ = self.intake(self.commit(f"gate {name}"))
            self.assertFalse(policy["ok"], name)
        self.git("reset", "-q", "--hard", self.base)
        self.git("clean", "-qfd")
        self.submit()
        (self.repo / B / "builders/ok.py").write_text('# import os is only a comment here\ndef f():\n    return "open eval exec"\n')
        policy, _ = self.intake(self.commit("fine"))
        self.assertTrue(policy["ok"], policy["errors"])

    def test_branch_must_contain_the_base_tip(self):
        self.submit()
        head = self.commit("submission")
        self.git("checkout", "-q", "-b", "moved", self.base)
        (self.repo / B / "builders/paper.py").write_text("# main moved on\n")
        tip = self.commit("another submission landed")
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["intake", "--repo", str(self.repo), "--base", self.base, "--head", head, "--tip", tip, "--out", str(out)])
        policy = json.loads((out / "policy.json").read_text())
        self.assertFalse(policy["ok"])
        self.assertIn("update it", " ".join(policy["errors"]))

    def test_registry_rewrite_is_refused(self):
        registry = json.loads((self.repo / B / "architectures.json").read_text())
        registry["architectures"][0]["mechanism"] = "rewritten"
        (self.repo / B / "architectures.json").write_text(json.dumps(registry, indent=1) + "\n")
        self.submit()
        policy, _ = self.intake(self.commit("rewrite"))
        self.assertFalse(policy["ok"])


if __name__ == "__main__":
    unittest.main()
