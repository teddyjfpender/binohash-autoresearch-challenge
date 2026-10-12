"""The website feed: derived JSON under data/site/, rebuilt from the ledgers.

`sources.json` and each `<challenge>/leaderboard.json` are derived and never edited by hand;
`activation.json` and each `<challenge>/challenge.json` are authored. `sources.json` is the single
entry point a site reads; it names every other file. All figures come from the ledger rows.
"""
from __future__ import annotations

import json
import pathlib

from . import ledger
from .common import ROOT, Challenge, challenges

SITE = ROOT / "data" / "site"


def _row(row: dict) -> dict:
    return {
        "unixTime": int(row["unix_time"]), "track": row["track"], "architecture": row["architecture"],
        "bytes": int(row["bytes"]), "opcodes": int(row["opcodes"]), "workBits": float(row["work_bits"]),
        "score": float(row["score"]), "securityBits": float(row["security_bits"]), "lanes": int(row["lanes"]),
        "engine": row["engine"], "instanceSha256": row["instance_sha256"],
        "verifierSha256": row["verifier_sha256"], "commit": row["commit"],
        "pr": int(row["pr"]) if row["pr"].isdigit() else None, "author": row["author"] or None,
        "model": row["model"] or None, "harness": row["harness"] or None, "submission": row["submission"],
        "kind": row["kind"], "standing": [s for s in row["standing"].split(",") if s], "note": row["note"],
    }


AXES = ("bytes", "opcodes", "workBits")


def _front(rows: list[dict]) -> list[dict]:
    """The (bytes, opcodes, work) Pareto front: the rows no other row matches or beats on all three."""
    def dominated(row: dict) -> bool:
        return any(other is not row and all(other[a] <= row[a] for a in AXES)
                   and (any(other[a] < row[a] for a in AXES) or other["unixTime"] < row["unixTime"]) for other in rows)
    return sorted((r for r in rows if not dominated(r)), key=lambda r: tuple(r[a] for a in AXES))


def _running_best(rows: list[dict]) -> list[dict]:
    best, steps = float("inf"), []
    for row in rows:
        if row["score"] < best:
            best = row["score"]
            steps.append(row)
    return steps


def leaderboard(challenge: Challenge) -> dict:
    raw = ledger.read(challenge.ledger)
    rows = [_row(r) for r in raw]
    architectures = challenge.architectures()
    targets = challenge.targets()
    tracks = []
    for name, track in challenge.tracks.items():
        mine = [r for r in rows if r["track"] == name]
        by_arch = []
        for arch_id, arch in architectures.items():
            instances = [r for r in mine if r["architecture"] == arch_id]
            if not instances:
                continue
            by_arch.append({
                "id": arch_id, "name": arch["name"], "parent": arch.get("parent"),
                "instances": len(instances), "firstUnixTime": min(r["unixTime"] for r in instances),
                "elite": min(instances, key=lambda r: (r["score"], r["bytes"])),
                "fewestBytes": min(instances, key=lambda r: (r["bytes"], r["score"])),
                "fewestOpcodes": min(instances, key=lambda r: (r["opcodes"], r["score"])),
                "leastWork": min(instances, key=lambda r: (r["workBits"], r["score"])),
                "history": _running_best(instances),
            })
        by_arch.sort(key=lambda a: a["elite"]["score"])
        best = min(mine, key=lambda r: (r["score"], r["bytes"])) if mine else None
        baseline = next((r for r in mine if r["submission"] == track.get("baseline", {}).get("submission")), None)
        tracks.append({
            "track": name, "title": track["title"], "spec": track["spec"],
            "securityFloorBits": float(track["standard"]["floorBits"]),
            "instances": len(mine), "best": best,
            # The construction the challenge starts from, as this evaluator counts it, and how far
            # below it the best instance is (a share of the baseline score, 0..1).
            "baseline": baseline,
            "belowBaseline": round(1 - best["score"] / baseline["score"], 6) if best and baseline else None,
            "architectures": by_arch, "front": _front(mine), "history": _running_best(mine),
            "targets": [t for t in targets if t["track"] == name],
        })
    return {
        "schema": "bac-leaderboard-v1", "challenge": challenge.id,
        "metric": challenge.contract["metric"], "ledger": f"{challenge.path}/{challenge.contract['ledger']}",
        # The row count and the last row's MAC: a later ledger must extend this one.
        "ledgerRows": len(rows), "ledgerHead": raw[-1]["mac"] if raw else None, "tracks": tracks,
    }


def sources(all_challenges: list[Challenge]) -> dict:
    return {
        "schema": "bac-site-sources-v1",
        "registry": "challenges.json",
        "activation": "data/site/activation.json",
        "challenges": {
            c.id: {
                "benchmark": f"{c.path}/benchmark.json",
                "architectures": f"{c.path}/{c.contract['architectures']}",
                "targets": f"{c.path}/{c.contract.get('targets', 'targets.json')}",
                "ledger": f"{c.path}/{c.contract['ledger']}",
                "leaderboard": f"data/site/{c.id}/leaderboard.json",
                "content": f"data/site/{c.id}/challenge.json",
                # Measurements of the instances the board starts from; evidence, not rows.
                **({"startingBoard": f"{c.path}/starting-board.json"} if (c.dir / "starting-board.json").exists() else {}),
            }
            for c in all_challenges
        },
    }


def render(value) -> str:
    return json.dumps(value, indent=1, ensure_ascii=False) + "\n"


def outputs() -> dict[pathlib.Path, str]:
    all_challenges = challenges()
    files = {SITE / "sources.json": render(sources(all_challenges))}
    for challenge in all_challenges:
        files[SITE / challenge.id / "leaderboard.json"] = render(leaderboard(challenge))
    return files


def export(check: bool = False) -> list[str]:
    """Write the derived files, or with `check` return the ones that are stale."""
    stale = []
    for path, text in outputs().items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(str(path.relative_to(ROOT)))
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
    return stale
