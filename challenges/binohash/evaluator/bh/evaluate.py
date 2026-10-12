"""Validate an instance and count it: `python3 -m bh.evaluate --root DIR --spec ID`.

Reads DIR/instance.json and writes DIR/score.json. Exit status 0 means every check passed on
every lane; anything else is a rejection, with the stage and the reason on stderr and in
score.json. Without `--seed` the lanes are derived from the instance itself, which is a check
for the builder's author and not a result (spec/VALIDATION.md).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import time
from decimal import Decimal

from .instance import Reject
from .judge import Judge

SPECS = pathlib.Path(__file__).resolve().parents[2] / "specs"
PUBLIC_SEED = b"bh-public-lanes-v1|"


def load_spec(name: str) -> dict:
    spec = json.loads((SPECS / f"{name}.json").read_text(encoding="utf-8"))
    if spec.get("schema") != "bh-spec-v1" or spec.get("id") != name:
        raise SystemExit(f"specs/{name}.json is not a bh-spec-v1 file for {name}")
    return spec


def plain(value):
    """JSON-ready copy: decimals to fixed six-place strings, so the file is the same everywhere."""
    if isinstance(value, Decimal):
        return f"{value:.6f}"
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="bh.evaluate", description=__doc__)
    parser.add_argument("--root", default=".", help="directory holding instance.json; score.json is written here")
    parser.add_argument("--spec", required=True, help="pinned spec id, e.g. bh1-standard")
    parser.add_argument("--stage", choices=("screen", "full"), default="full")
    parser.add_argument("--lanes", type=int, help="override the stage's lane count")
    parser.add_argument("--seed", help="64 hex characters; the judge passes the ledger-key seed")
    parser.add_argument("--vectors", help="write the spends of the first lanes for the Core comparison")
    parser.add_argument("--core", help="path to tools/core's cchk; replay those spends through Bitcoin Core")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root)
    spec = load_spec(args.spec)
    stage = spec["validation"][args.stage]
    lanes = args.lanes or stage["lanes"]
    raw = (root / "instance.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    seed = bytes.fromhex(args.seed) if args.seed else hashlib.sha256(PUBLIC_SEED + digest.encode()).digest()
    if len(seed) != 32 or lanes < 1:
        raise SystemExit("the seed must be 32 bytes and at least one lane is required")
    score = root / "score.json"
    score.unlink(missing_ok=True)
    started = time.time()
    result = {"schema": "bh-score-v1", "spec": spec["id"], "model": spec["model"], "work_model": spec["work"],
              "stage": args.stage, "seed": seed.hex(), "seed_kind": "judge" if args.seed else "public",
              "digests": {"instance": digest}}
    try:
        judge = Judge(raw, spec, seed)
        judge.run(lanes, min(lanes, stage["auditLanes"]), min(lanes, stage["vectorLanes"]))
    except Reject as exc:
        result.update(status="REJECTED", stage_failed=exc.stage, reason=exc.reason)
        score.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        print(f"REJECTED at {exc.stage}: {exc.reason}", file=sys.stderr)
        return 1
    vectors = "".join(f"{name} {locking.hex()} {spend.hex()} 1 {int(verdict)}\n"
                      for name, locking, spend, verdict in judge.vectors)
    if args.vectors:
        pathlib.Path(args.vectors).write_text(vectors, encoding="utf-8")
    engine = f"reference-{lanes}"
    if args.core:
        replay = subprocess.run([args.core], input=vectors, capture_output=True, text=True, check=False)
        lines = replay.stdout.splitlines()
        agreed = [line for line in lines if line.startswith("PASS ")]
        if replay.returncode != 0 or len(agreed) != len(judge.vectors) or not judge.vectors:
            result.update(status="REJECTED", stage_failed="core",
                          reason="the reference engine and Bitcoin Core disagree; this is a fault of the evaluator",
                          core=[line for line in lines if not line.startswith("PASS ")][:20])
            score.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
            print("REJECTED at core: the reference engine and Bitcoin Core disagree:\n" + replay.stdout[-2000:], file=sys.stderr)
            return 2
        engine += f"+core-{len(agreed)}"
    result.update(status="OK", metrics=plain(judge.metrics), checks=judge.counts, engine=engine)
    score.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    m = judge.metrics
    print(f"OK  {engine}: {lanes} lanes, {judge.counts['mutants']} altered spends ({judge.counts['mutants_accepted']} accepted, "
          f"all sound), {time.time() - started:.1f}s")
    print(f"    bytes {m['bytes']} (locking {m['locking_bytes']} + unlocking {m['unlocking_bytes']})  "
          f"opcodes {m['opcodes']}  work 2^{m['work_bits']:.3f} compressions  "
          f"security {m['security_bits']:.3f} bits (floor {spec['floorBits']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
