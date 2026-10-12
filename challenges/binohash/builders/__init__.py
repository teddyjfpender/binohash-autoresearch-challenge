"""Instance builders: the editable surface of the challenge.

`build(knobs)` receives the submission's build knobs (the `BINO_*` entries of its manifest) and
returns an instance as a JSON-ready dict in the `bh-instance-v1` format (spec/DESIGN.md). It must
be deterministic: the same knobs must give the same bytes on every machine, because a recorded
instance is identified by its digest. Builders do no input or output; the trusted runner writes
the file.
"""
from . import late, paper

BUILDERS = {
    "late": late.build,
    "paper": paper.build,
}


def build(knobs: dict) -> dict:
    name = knobs.get("BINO_BUILDER", "paper")
    if name not in BUILDERS:
        raise ValueError(f"unknown BINO_BUILDER '{name}'; builders: {', '.join(sorted(BUILDERS))}")
    return BUILDERS[name](knobs)
