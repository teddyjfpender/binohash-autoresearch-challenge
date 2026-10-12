"""The judge's pull-request comment and the labels that go with it.

Inputs are the JSON files the workflow's jobs produced. Any of them may be missing when an
earlier job failed; the report says which stage stopped the submission.
"""
from __future__ import annotations

import json
import pathlib
import re

MARKER = "<!-- bac-judge -->"
LABELS = {
    "invalid": "submission-invalid",
    "rejected": "submission-not-recorded",
    "review": "needs-architecture-review",
    "validated": "submission-validated",
    "recorded": "submission-recorded",
}


def clean(text) -> str:
    """Untrusted text for a comment: one line, no markup that could render or mention."""
    return re.sub(r"[^A-Za-z0-9 _.,:;=+~()/'`-]", "?", str(text))[:300]


def _load(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def build(directory: pathlib.Path, stages: dict[str, str], approved: bool, run_url: str) -> dict:
    """Return {"outcome", "label", "body", "merge"} for the judge's verdict."""
    policy = _load(directory / "policy.json")
    manifest = _load(directory / "manifest.json")
    row = _load(directory / "row.json")
    decision = _load(directory / "decision.json")
    lines = [MARKER, "## Judge report", ""]
    outcome, merge = "invalid", False

    def stop(reason: str, details: list[str] | None = None) -> dict:
        lines.append(f"**Not valid.** {reason}")
        lines.extend(f"- {clean(d)}" for d in (details or [])[:20])
        lines.extend(["", f"[Workflow run]({run_url})"])
        return {"outcome": "invalid", "label": LABELS["invalid"], "body": "\n".join(lines) + "\n", "merge": False}

    if policy is None:
        return stop("The path policy could not be evaluated.")
    if not policy.get("ok"):
        return stop("The pull request changes paths a submission may not change, or its submission directory is malformed.", policy.get("errors"))
    if manifest is None:
        return stop("`submission.json` or `NOTES.md` did not pass the manifest check. See the intake job's log.")
    lines += [
        f"**{manifest['challenge']} / {manifest['track']} / `{manifest['id']}`** · architecture `{manifest['architecture']}`",
        "",
    ]
    if stages.get("build") != "success":
        return stop("The instance did not build, a recorded instance changed, or the builder did not produce instance.json. "
                    "New behaviour must sit behind a new build knob so recorded instances stay byte-identical.")
    if stages.get("evaluate") != "success" or row is None or decision is None:
        if stages.get("evaluate") in ("failure", None) and row is None:
            return stop("The trusted evaluator did not pass the instance, or the evaluation job could not run. "
                        "The evaluate job's log has the failing check and reason, or the infrastructure error; "
                        "a maintainer can add the label `rejudge` to run it again.")
        return stop("The trusted evaluator rejected the instance. See the evaluate job's log for the failing check and reason.")

    lines += [
        "| Bytes | Opcodes | Honest work | Score (bytes x opcodes x work) | Security | Lanes | Engines |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        f"| {int(row['bytes']):,} | {int(row['opcodes'])} | 2^{row['work_bits']} | {float(row['score']):,.3f} "
        f"| {row['security_bits']} bits | {int(row['lanes']):,} | `{row['engine']}` |",
        "",
        f"- Instance `instance_sha256`: `{row['instance_sha256']}`",
        f"- Lane seed: `{row['seed']}`",
        f"- Evaluator `verifier_sha256`: `{row['verifier_sha256']}`",
        "",
    ]
    claimed = manifest.get("claimed") or {}
    if claimed:
        lines += [f"Claimed: {claimed.get('bytes', '?')} bytes, {claimed.get('opcodes', '?')} opcodes, "
                  f"2^{claimed.get('work_bits', '?')} compressions.", ""]
    if not decision["accepted"]:
        outcome = "rejected"
        lines += [f"**Valid, not recorded.** {decision['reason'][0].upper()}{decision['reason'][1:]}.", ""]
    else:
        standing = ", ".join(f"`{s}`" for s in decision["standing"])
        reasons = []
        if policy.get("proposes_architecture"):
            reasons.append("it adds an architecture to the registry")
        if policy.get("classified") is None:
            reasons.append("its builder is new, so the declared architecture cannot be checked mechanically")
        if "new-architecture" in decision["standing"]:
            reasons.append("it would be the first instance of its architecture on this track")
        if reasons and not approved:
            outcome = "review"
            lines += [
                f"**Valid.** Standing: {standing}.",
                "",
                f"This submission waits for a maintainer because {'; '.join(reasons)}. A maintainer checks the "
                "declared architecture against the registry's rules and adds the label `architecture-approved`; "
                "the judge then runs again on this exact commit and records it. A new push needs a new approval.",
                "",
            ]
        else:
            outcome, merge = "validated", True
            lines += [f"**Valid.** Standing: {standing}. The bot will merge this pull request and record the row.", ""]
    lines += [f"[Workflow run]({run_url})"]
    return {"outcome": outcome, "label": LABELS[outcome], "body": "\n".join(lines) + "\n", "merge": merge}
