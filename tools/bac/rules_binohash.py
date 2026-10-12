"""Binohash: which registry architecture a manifest's build knobs produce, for the shipped builders.

The architecture a submission declares decides which board it competes on, so it cannot be left
to the manifest alone. For the builders that ship with the challenge the answer follows from the
build knobs. A builder this file does not know (new builder code) returns None, and the
submission then needs a maintainer's approval.
"""
from __future__ import annotations

SHIPPED = {
    "paper": "rolled-subset",
    "late": "rolled-subset",  # the same tables and loop, laid out differently
    "pairs": "paired-table",  # recorded with standard/paired-3round-pin5
}


def architecture_of(build: dict[str, str]) -> str | None:
    return SHIPPED.get(build.get("BINO_BUILDER", "paper"))
