"""The results ledger: one append-only TSV per challenge, one row per validated instance.

A row is written only by the judge after the trusted evaluator has passed the instance. Each row
names the exact instance (SHA-256 of its file), the evaluator that passed it
(`verifier_sha256`), the lane seed it was validated with, and carries a chained HMAC-SHA256
(`mac`) under the ledger key, so rows cannot be added, changed, reordered or removed without the
key. See spec/LEDGER.md.
"""
from __future__ import annotations

import decimal
import hashlib
import hmac
import pathlib
from decimal import Decimal

from .common import HEX64, ContractError

COLUMNS = [
    "unix_time", "track", "spec", "architecture", "bytes", "opcodes", "work_bits", "score", "security_bits",
    "lanes", "engine", "seed", "instance_sha256", "verifier_sha256", "commit", "pr", "author", "model",
    "harness", "submission", "kind", "standing", "status", "note", "mac",
]
KINDS = ("historical", "submission")
STANDINGS = ("new-architecture", "architecture-elite", "front")
UNSIGNED = "unsigned"
GENESIS = "0" * 64
SEED_DOMAIN = b"bac-lane-seed-v1"
MAC_DOMAIN = b"bac-ledger-row-v1"
WORK_UNIT_BITS = 40  # the score counts work in units of 2^40 SHA-256 compressions
_CTX = decimal.Context(prec=40, rounding=decimal.ROUND_HALF_EVEN)
_LN2 = _CTX.ln(Decimal(2))


def derive_seed(key: bytes, instance: str) -> str:
    """The lane seed of an instance: unpredictable without the key, reproducible with it, and
    published in the row so anyone can re-run the exact evaluation."""
    if not HEX64.match(instance):
        raise ContractError("derive_seed: a SHA-256 hex digest is required")
    return hmac.new(key, SEED_DOMAIN + b"|" + instance.encode(), hashlib.sha256).hexdigest()


def clean(text) -> str:
    return " ".join(str(text).replace("\t", " ").split())


def row_message(row: dict) -> bytes:
    return "\t".join(clean(row[c]) for c in COLUMNS if c != "mac").encode("utf-8")


def mac(key: bytes, previous: str, row: dict) -> str:
    return hmac.new(key, MAC_DOMAIN + b"|" + previous.encode() + b"|" + row_message(row), hashlib.sha256).hexdigest()


def read(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0].split("\t") != COLUMNS:
        raise ContractError(f"{path.name}: the header must be exactly the ledger columns")
    rows = []
    for number, line in enumerate(lines[1:], start=2):
        cells = line.split("\t")
        if len(cells) != len(COLUMNS):
            raise ContractError(f"{path.name}:{number}: {len(cells)} cells, {len(COLUMNS)} expected")
        rows.append(dict(zip(COLUMNS, cells)))
    return rows


def write(path: pathlib.Path, rows: list[dict]) -> None:
    lines = ["\t".join(COLUMNS)] + ["\t".join(clean(r[c]) for c in COLUMNS) for r in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sign(key: bytes | None, rows: list[dict]) -> None:
    """Recompute the MAC chain in place (ledger generation; the bot signs appended rows)."""
    previous = GENESIS
    for row in rows:
        row["mac"] = mac(key, previous, row) if key else UNSIGNED
        previous = row["mac"]


def verify_chain(key: bytes, rows: list[dict]) -> list[str]:
    errors, previous = [], GENESIS
    for number, row in enumerate(rows, start=2):
        if not hmac.compare_digest(row["mac"], mac(key, previous, row)):
            errors.append(f"line {number}: MAC does not verify")
        previous = row["mac"]
    return errors


def _f(row: dict, column: str) -> float:
    return float(row[column])


def score_of(size: int, opcodes: int, work_bits: str) -> str:
    """The challenge score, bytes x opcodes x work, computed exactly from the row's own cells.

    Work is 2^work_bits SHA-256 compressions, counted in units of 2^40. Decimal arithmetic with
    correctly rounded exp and ln makes the result the same on every machine.
    """
    work = _CTX.exp(_CTX.multiply(Decimal(work_bits) - WORK_UNIT_BITS, _LN2))
    return f"{_CTX.multiply(Decimal(size * opcodes), work):.3f}"


def check_rows(rows: list[dict], tracks: dict[str, dict], architectures: dict[str, dict], signed: bool) -> list[str]:
    """Static integrity of a ledger: formats, track and architecture names, ordering, uniqueness."""
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    last_time = 0
    for number, row in enumerate(rows, start=2):
        where = f"line {number}"
        try:
            when, size, opcodes, lanes = int(row["unix_time"]), int(row["bytes"]), int(row["opcodes"]), int(row["lanes"])
            work, security = Decimal(row["work_bits"]), Decimal(row["security_bits"])
            _f(row, "score")
        except (ValueError, decimal.InvalidOperation):
            errors.append(f"{where}: unreadable number")
            continue
        if when < last_time:
            errors.append(f"{where}: rows must be in time order")
        last_time = max(last_time, when)
        track = tracks.get(row["track"])
        if track is None or row["spec"] != track["spec"]:
            errors.append(f"{where}: unknown track or wrong spec")
        elif security < Decimal(track["standard"]["floorBits"]):
            errors.append(f"{where}: security_bits is below the track's floor")
        if row["architecture"] not in architectures:
            errors.append(f"{where}: architecture '{row['architecture']}' is not in the registry")
        if size <= 0 or opcodes <= 0 or lanes <= 0 or not 0 < work < 512:
            errors.append(f"{where}: counts must be positive")
        elif row["score"] != score_of(size, opcodes, row["work_bits"]):
            errors.append(f"{where}: score is not bytes x opcodes x work")
        for column in ("seed", "instance_sha256", "verifier_sha256"):
            if not HEX64.match(row[column]):
                errors.append(f"{where}: {column} must be 64 hex characters")
        if row["kind"] not in KINDS or row["status"] != "OK":
            errors.append(f"{where}: kind must be one of {KINDS} and status OK")
        if any(s not in STANDINGS for s in row["standing"].split(",") if s):
            errors.append(f"{where}: unknown standing")
        key = (row["track"], row["instance_sha256"])
        if key in seen:
            errors.append(f"{where}: the same instance is already in the ledger")
        seen.add(key)
        if signed and not HEX64.match(row["mac"]):
            errors.append(f"{where}: unsigned row")
    return errors


def standing(rows: list[dict], candidate: dict, min_improvement_bips: int) -> tuple[list[str], str]:
    """Where a validated instance stands against the ledger. Returns (standings, reason).

    Architecture comes first: an instance is recorded if it is the first of its architecture, or
    beats that architecture's best score, or advances the track's (bytes, opcodes, work) front:
    it needs less work, by the margin, than every recorded instance that is no larger in bytes
    and uses no more opcodes. The counts are exact, so the margin is not for noise; it keeps
    one-step parameter nudges from filling the board.
    """
    eps = min_improvement_bips / 10_000
    track = [r for r in rows if r["track"] == candidate["track"]]
    if any(r["instance_sha256"] == candidate["instance_sha256"] for r in track):
        return [], "this exact instance is already in the ledger"
    size, opcodes, score = int(candidate["bytes"]), int(candidate["opcodes"]), _f(candidate, "score")
    work = 2.0 ** _f(candidate, "work_bits")
    result = []
    same = [r for r in track if r["architecture"] == candidate["architecture"]]
    if not same:
        result.append("new-architecture")
    elif score < min(_f(r, "score") for r in same) * (1 - eps):
        result.append("architecture-elite")
    rivals = [r for r in track if int(r["bytes"]) <= size and int(r["opcodes"]) <= opcodes]
    if all(work < 2.0 ** _f(r, "work_bits") * (1 - eps) for r in rivals):
        result.append("front")
    if result:
        return result, ""
    best = min(same, key=lambda r: _f(r, "score"))
    return [], (
        f"valid, but it neither beats the best {candidate['architecture']} score "
        f"({best['bytes']} bytes x {best['opcodes']} opcodes x 2^{best['work_bits']} compressions) by "
        f"{min_improvement_bips / 100:g}% nor needs {min_improvement_bips / 100:g}% less work than every recorded "
        f"instance with at most {size} bytes and {opcodes} opcodes"
    )


def row_from_score(score: dict, *, track: dict, architecture: str, seed: str, verifier: str,
                   unix_time: int, commit: str, pr: str, author: str, model: str, harness: str,
                   submission: str, kind: str, note: str, engine: str = "") -> dict:
    """A ledger row from the trusted evaluator's score.json."""
    if score.get("status") != "OK":
        raise ContractError("score.json does not report a validated instance")
    if score["spec"] != track["spec"]:
        raise ContractError(f"score.json is for spec {score['spec']}, the track needs {track['spec']}")
    if score["seed"] != seed:
        raise ContractError("score.json was not produced with this seed")
    metrics = score["metrics"]
    work_bits, security = f"{Decimal(metrics['work_bits']):.3f}", f"{Decimal(metrics['security_bits']):.3f}"
    if Decimal(metrics["security_bits"]) < Decimal(track["standard"]["floorBits"]):
        raise ContractError(f"security {security} bits is below the track's floor of {track['standard']['floorBits']}")
    size, opcodes = int(metrics["bytes"]), int(metrics["opcodes"])
    return {
        "unix_time": str(unix_time), "track": track["name"], "spec": track["spec"], "architecture": architecture,
        "bytes": str(size), "opcodes": str(opcodes), "work_bits": work_bits,
        "score": score_of(size, opcodes, work_bits), "security_bits": security,
        "lanes": str(int(score["checks"]["lanes"])), "engine": engine or score["engine"], "seed": seed,
        "instance_sha256": score["digests"]["instance"], "verifier_sha256": verifier, "commit": commit, "pr": pr,
        "author": author, "model": model, "harness": harness, "submission": submission, "kind": kind,
        "standing": "", "status": "OK", "note": clean(note), "mac": UNSIGNED,
    }
