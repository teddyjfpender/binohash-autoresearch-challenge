"""Recorded and catalogued instances still build byte for byte from their manifests."""
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Pins(unittest.TestCase):
    def test_recorded_instances_rebuild(self):
        spec = importlib.util.spec_from_file_location("verify_submissions", ROOT / "tools" / "verify_submissions.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        wanted = module.expected()
        self.assertGreaterEqual(len(wanted), 2)
        for submission, digest in wanted.items():
            self.assertEqual(module.digest_of(submission), digest, submission)


if __name__ == "__main__":
    unittest.main()
