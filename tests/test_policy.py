import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

from bac import policy  # noqa: E402
from bac.policy import Change  # noqa: E402

B = "challenges/binohash"
SUB = f"{B}/submissions/standard/my-instance"


def added(path):
    return Change("A", "000000", "100644", path)


def modified(path, mode="100644"):
    return Change("M", "100644", mode, path)


class PolicyTest(unittest.TestCase):
    def submission(self, *extra):
        return [added(f"{SUB}/submission.json"), added(f"{SUB}/NOTES.md"), *extra]

    def test_non_submission_pull_request_is_not_judged(self):
        verdict = policy.evaluate([modified("README.md"), modified(f"{B}/evaluator/bh/judge.py")])
        self.assertFalse(verdict.is_submission)

    def test_minimal_submission(self):
        verdict = policy.evaluate(self.submission())
        self.assertTrue(verdict.ok, verdict.errors)
        self.assertEqual((verdict.challenge, verdict.track, verdict.submission_id), ("binohash", "standard", "my-instance"))
        self.assertFalse(verdict.touches_code)

    def test_code_and_registry(self):
        verdict = policy.evaluate(self.submission(modified(f"{B}/builders/paper.py"), added(f"{B}/builders/late_pool.py"),
                                                  modified(f"{B}/architectures.json")))
        self.assertTrue(verdict.ok, verdict.errors)
        self.assertTrue(verdict.touches_code and verdict.proposes_architecture)

    def test_trusted_paths_are_refused(self):
        for path in (f"{B}/evaluator/bh/judge.py", f"{B}/evaluator/run_builder.py", f"{B}/specs/bh1-standard.json",
                     f"{B}/results.tsv", f"{B}/benchmark.json", f"{B}/tests/test_evaluator.py", f"{B}/benchmark.sh",
                     f"{B}/starting-board.json", f"{B}/tools/core/src/main.rs", f"{B}/spec/SECURITY-MODEL.md",
                     ".github/workflows/judge.yml", "tools/bac/ledger.py", "challenge.py", "data/site/sources.json",
                     f"{B}/builders2/x.py"):
            verdict = policy.evaluate(self.submission(modified(path)))
            self.assertFalse(verdict.ok, path)

    def test_submission_shape(self):
        cases = [
            [added(f"{SUB}/submission.json"), added(f"{SUB}/NOTES.md"), added(f"{SUB}/instance.json")],
            [added(f"{SUB}/submission.json"), added(f"{SUB}/NOTES.md"), added(f"{B}/submissions/high/other/submission.json")],
            [added(f"{B}/submissions/nosuchtrack/x-y-z/submission.json")],
            [added(f"{B}/submissions/standard/Bad_Id/submission.json")],
            [modified(f"{SUB}/submission.json")],
            [Change("D", "100644", "000000", f"{SUB}/NOTES.md")],
            [added(f"{B}/submissions/standard/submission.json")],
        ]
        for changes in cases:
            self.assertFalse(policy.evaluate(changes).ok, changes)

    def test_modes_and_paths(self):
        self.assertFalse(policy.evaluate(self.submission(modified(f"{B}/builders/a.py", "100755"))).ok)
        self.assertFalse(policy.evaluate(self.submission(Change("A", "000000", "120000", f"{B}/builders/link"))).ok)
        self.assertFalse(policy.evaluate(self.submission(added(f"{B}/builders/../evaluator/x.py"))).ok)
        self.assertFalse(policy.evaluate(self.submission(Change("R", "100644", "100644", f"{B}/builders/a.py"))).ok)
        self.assertFalse(policy.evaluate(self.submission(added(f"{B}/builders/helper.so"))).ok)

    def test_parse_raw(self):
        raw = b":100644 100644 aaaa bbbb M\0challenges/binohash/builders/a.py\0:000000 100644 0000 cccc A\0x y\0"
        changes = policy.parse_raw(raw)
        self.assertEqual([(c.status, c.path) for c in changes], [("M", "challenges/binohash/builders/a.py"), ("A", "x y")])

    def test_registry_append_only(self):
        entry = {"id": "new-arch", "name": "New", "mechanism": "m" * 200, "distinguishing": "d" * 100, "references": []}
        old = {"schema": "s", "architectures": [{"id": "a"}]}
        self.assertEqual(policy.registry_is_append_only(old, {"schema": "s", "architectures": [{"id": "a"}, entry]}), [])
        self.assertTrue(policy.registry_is_append_only(old, {"schema": "s", "architectures": [entry, {"id": "a"}]}))
        self.assertTrue(policy.registry_is_append_only(old, {"schema": "s", "architectures": [{"id": "a", "name": "x"}, entry]}))
        self.assertTrue(policy.registry_is_append_only(old, {"schema": "t", "architectures": [{"id": "a"}, entry]}))
        self.assertTrue(policy.registry_is_append_only(old, {"schema": "s", "architectures": [{"id": "a"}, {**entry, "mechanism": "short"}]}))
        self.assertTrue(policy.registry_is_append_only(old, {"schema": "s", "architectures": [{"id": "a"}, {**entry, "id": "a"}]}))
        self.assertTrue(policy.registry_is_append_only(old, old))


class SourceScanTest(unittest.TestCase):
    def scan(self, body: str, path: str = "challenges/binohash/builders/x.py"):
        return policy.scan_source(path, body.encode())

    def test_pure_builder_code_passes(self):
        body = (
            "from __future__ import annotations\n"
            "import hashlib\nimport math\n"
            "from bh import script as S\nfrom bh.tx import SINGLE_BUG_DIGEST\nfrom .kit import Asm\n\n"
            "class Layout:\n    def __init__(self, n):\n        self.n = n\n\n"
            "def build(knobs):\n    'open and eval are only words in this string'\n"
            "    return {'schema': 'bh-instance-v1', 'n': math.comb(4, 2), 'h': hashlib.sha256(b'x').hexdigest()}\n"
        )
        self.assertEqual(self.scan(body), [])

    def test_everything_but_pure_computation_is_refused(self):
        for body in (
            "import os\n", "import subprocess\n", "from pathlib import Path\n", "import socket\n", "import importlib\n",
            "import bh.evaluate, sys\n", "from os import path as p\n", "import ctypes\n", "import builders.other, pickle\n",
            "x = open('/etc/passwd').read()\n", "eval('1+1')\n", "exec('pass')\n", "f = getattr(object, 'x')\n",
            "__import__('os')\n", "y = ().__class__.__bases__\n", "z = (1).__reduce__()\n", "__builtins__\n",
            "def f():\n    global state\n    state = 1\n", "breakpoint()\n", "compile('1', 'f', 'eval')\n",
        ):
            self.assertTrue(self.scan(body), body)

    def test_files_that_are_not_python(self):
        self.assertEqual(self.scan("anything, even import os", "challenges/binohash/builders/README.md"), [])
        self.assertTrue(self.scan("def f(:\n"))
        self.assertTrue(policy.scan_source("challenges/binohash/builders/x.py", b"\xff\xfe"))
        self.assertTrue(policy.scan_source("challenges/binohash/builders/x.py", b"#" * (policy.MAX_FILE_BYTES + 1)))


if __name__ == "__main__":
    unittest.main()
