"""Import path for the challenge's tests: the trusted evaluator and this directory."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for entry in (ROOT / "evaluator", ROOT / "tests"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))
