"""Run the builders with the manifest's knobs and write instance.json.

This runner is trusted; the `builders` package it imports is not. benchmark.sh runs it inside a
sandbox with a read-only filesystem and no network, and the evaluator reads the file it writes
as hostile data.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

KNOB = re.compile(r"\ABINO_[A-Z0-9_]+\Z")
RESERVED = {"BINO_SPEC", "BINO_STAGE", "BINO_OUT"}


def main() -> int:
    import builders  # noqa: PLC0415 - imported after the path is set

    knobs = {k: v for k, v in sorted(os.environ.items()) if KNOB.match(k) and k not in RESERVED}
    instance = builders.build(knobs)
    out = pathlib.Path(os.environ.get("BINO_OUT", ".")) / "instance.json"
    out.write_text(json.dumps(instance, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes) with knobs {knobs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
