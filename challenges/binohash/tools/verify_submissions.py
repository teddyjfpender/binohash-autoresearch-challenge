#!/usr/bin/env python3
"""Rebuild every recorded or catalogued instance from its manifest and compare digests.

A recorded instance is identified by the SHA-256 of its instance.json, so the builders must
keep producing the same bytes for the same knobs. This runs the builders in-process for every
row of results.tsv and every candidate of starting-board.json, and fails on any difference.
It executes builder code unconfined: run it on code you trust, or through
tools/ci/pins_sandboxed.sh, which is what the judge does.

    python3 tools/verify_submissions.py            # check
    python3 tools/verify_submissions.py --digests  # print `<submission> <digest>` for each
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "evaluator"))
sys.path.insert(0, str(HERE))


def expected() -> dict[str, str]:
    wanted: dict[str, str] = {}
    lines = (HERE / "results.tsv").read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    for line in lines[1:]:
        row = dict(zip(header, line.split("\t")))
        wanted[row["submission"]] = row["instance_sha256"]
    catalogue = HERE / "starting-board.json"
    if catalogue.exists():
        for candidate in json.loads(catalogue.read_text(encoding="utf-8"))["candidates"]:
            wanted.setdefault(candidate["submission"], candidate["instanceSha256"])
    return wanted


def digest_of(submission: str) -> str:
    import builders  # noqa: PLC0415 - imported after the path is set

    manifest = json.loads((HERE / "submissions" / submission / "submission.json").read_text(encoding="utf-8"))
    instance = builders.build(dict(sorted(manifest["build"].items())))
    data = json.dumps(instance, sort_keys=True, separators=(",", ":")) + "\n"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def main() -> int:
    show = "--digests" in sys.argv[1:]
    failed = 0
    wanted = expected()
    for submission, digest in sorted(wanted.items()):
        got = digest_of(submission)
        if show:
            print(f"{submission} {got}")
        elif got != digest:
            failed += 1
            print(f"FAIL {submission}: builds to {got}, recorded as {digest}")
    if not show:
        print(f"{len(wanted) - failed} of {len(wanted)} recorded instances rebuild byte for byte")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
