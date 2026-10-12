"""The instance file a builder emits (`bh-instance-v1`) and its static checks.

An instance is untrusted data. It holds the production locking script, a test twin at a puzzle
difficulty the judge can grind, and a description of how an honest spender unlocks it. Nothing
in it is believed: every field is either checked against the script bytes here or exercised by
the lanes in judge.py. The format is specified in spec/DESIGN.md.
"""
from __future__ import annotations

import json
import re

from . import script as S
from . import secp256k1 as ec
from .model import SIG_OVERHEAD, SizePuzzle, choose, overlap
from .tx import SINGLE_BUG_DIGEST

SCHEMA = "bh-instance-v1"
MAX_INSTANCE_BYTES = 2 << 20
HEX = re.compile(r"\A(?:[0-9a-f]{2})*\Z")
ID = re.compile(r"\A[a-z0-9_-]{1,32}\Z")
STRAIGHT_LINE_FORBIDDEN = {S.OP_IF, S.OP_NOTIF, S.OP_ELSE, S.OP_ENDIF, S.OP_VERIF, S.OP_VERNOTIF, S.OP_RETURN,
                           S.OP_CHECKLOCKTIMEVERIFY, S.OP_CHECKSEQUENCEVERIFY, S.OP_VER, S.OP_RESERVED,
                           S.OP_RESERVED1, S.OP_RESERVED2}
SLOT_ORDERS = ("any", "ascending", "descending")
INDEX_ENCODINGS = ("rank", "abs")
ROLES = ("pin", "round")
PIN_PUZZLES = 4  # one per sighash mode that is not SIGHASH_SINGLE


class Reject(Exception):
    """The instance does not meet the contract. `stage` names the check that refused it."""

    def __init__(self, stage: str, reason: str):
        super().__init__(f"{stage}: {reason}")
        self.stage, self.reason = stage, reason


def _hex(value, name: str, stage: str = "format") -> bytes:
    if not isinstance(value, str) or not HEX.match(value):
        raise Reject(stage, f"{name} must be lowercase hex")
    return bytes.fromhex(value)


def _int(value, name: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise Reject("format", f"{name} must be an integer in [{lo}, {hi}]")
    return value


def _keys(obj, name: str, required: set, optional: set = frozenset()) -> None:
    if not isinstance(obj, dict):
        raise Reject("format", f"{name} must be an object")
    if set(obj) - required - optional or required - set(obj):
        raise Reject("format", f"{name} needs exactly {sorted(required)} (optional {sorted(optional)})")


class Puzzle:
    def __init__(self, ident, role, key_at, size_at, prod: SizePuzzle, test: SizePuzzle):
        self.id, self.role, self.key_at, self.size_at, self.prod, self.test = ident, role, key_at, size_at, prod, test


class Round:
    def __init__(self, puzzle, t, pool, commit, keys, preimages, slots):
        self.puzzle, self.t, self.pool, self.commit = puzzle, t, pool, commit
        self.keys, self.preimages, self.slots = keys, preimages, slots
        self.n = len(pool)
        self.selections = choose(self.n, t)


class Instance:
    """A parsed instance whose static checks have passed."""

    def __init__(self, raw: bytes, limits: dict):
        if len(raw) > MAX_INSTANCE_BYTES:
            raise Reject("format", f"instance larger than {MAX_INSTANCE_BYTES} bytes")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise Reject("format", f"not JSON ({type(exc).__name__})") from exc
        _keys(data, "instance", {"schema", "locking", "locking_test", "puzzles", "rounds", "witness"})
        if data["schema"] != SCHEMA:
            raise Reject("format", f"schema must be {SCHEMA}")
        self.limits = limits
        self.locking = _hex(data["locking"], "locking")
        self.locking_test = _hex(data["locking_test"], "locking_test")
        self._scripts()
        self._puzzles(data["puzzles"])
        self._twin()
        self._rounds(data["rounds"])
        self._witness(data["witness"])

    # -- scripts -------------------------------------------------------------------------------

    def _scripts(self) -> None:
        for name, code in (("locking", self.locking), ("locking_test", self.locking_test)):
            if not 0 < len(code) <= S.MAX_SCRIPT_BYTES:
                raise Reject("limits", f"{name} is {len(code)} bytes; consensus allows 1 to {S.MAX_SCRIPT_BYTES}")
            try:
                ops = S.parse(code)
            except S.ScriptError as exc:
                raise Reject("limits", f"{name}: {exc}") from exc
            for offset, opcode, data, _end in ops:
                if data is not None and len(data) > S.MAX_ELEMENT_BYTES:
                    raise Reject("limits", f"{name}: push of {len(data)} bytes at offset {offset}")
                if data is None and (opcode in S.DISABLED or opcode > S.OP_NOP10):
                    raise Reject("limits", f"{name}: opcode 0x{opcode:02x} at offset {offset} always fails")
                if data is None and opcode in STRAIGHT_LINE_FORBIDDEN:
                    raise Reject("straight-line", f"{name}: {S.NAMES.get(opcode, hex(opcode))} at offset {offset}; "
                                 "the audited model covers scripts in which every operation executes on every spend")
        if len(self.locking) != len(self.locking_test):
            raise Reject("twin", "the test script must have the length of the production script")
        self.ops = {offset: (opcode, data, end) for offset, opcode, data, end in S.parse(self.locking)}
        self.ops_test = {offset: (opcode, data, end) for offset, opcode, data, end in S.parse(self.locking_test)}

    def push_at(self, offset: int, name: str, test: bool = False) -> bytes:
        entry = (self.ops_test if test else self.ops).get(offset)
        if entry is None or entry[1] is None:
            raise Reject("structure", f"{name}: offset {offset} is not a data push of the locking script")
        return entry[1]

    def data_span(self, offset: int) -> tuple[int, int]:
        _opcode, data, end = self.ops[offset]
        return end - len(data), end

    # -- puzzles -------------------------------------------------------------------------------

    def _puzzles(self, items) -> None:
        if not isinstance(items, list) or not 1 <= len(items) <= PIN_PUZZLES + self.limits["maxRounds"]:
            raise Reject("format", "puzzles must be a non-empty list")
        self.puzzles: dict[str, Puzzle] = {}
        used: set[int] = set()
        for item in items:
            _keys(item, "puzzle", {"id", "role", "key_at", "size_at", "dlog", "dlog_test"})
            ident = item["id"]
            if not isinstance(ident, str) or not ID.match(ident) or ident in self.puzzles:
                raise Reject("format", "puzzle ids must be distinct short slugs")
            if item["role"] not in ROLES:
                raise Reject("format", f"puzzle {ident}: role must be one of {ROLES}")
            key_at = _int(item["key_at"], f"puzzle {ident} key_at", 0, len(self.locking))
            size_at = _int(item["size_at"], f"puzzle {ident} size_at", 0, len(self.locking))
            if {key_at, size_at} & used or key_at == size_at:
                raise Reject("structure", f"puzzle {ident}: its key and size pushes are shared with another puzzle")
            used |= {key_at, size_at}
            sides = []
            for test, field in ((False, "dlog"), (True, "dlog_test")):
                dlog = int.from_bytes(_hex(item[field], f"puzzle {ident} {field}"), "big")
                key = self.push_at(key_at, f"puzzle {ident} key", test)
                if not 0 < dlog < ec.N or key != ec.compressed(ec.mul(dlog)):
                    raise Reject("puzzle-key", f"puzzle {ident}: the {'test' if test else 'production'} key is not "
                                 "the compressed point d*G of its disclosed discrete logarithm")
                size_push = self.push_at(size_at, f"puzzle {ident} size", test)
                try:
                    size = S.num_decode(size_push)
                    sides.append(SizePuzzle(dlog, size))
                except (S.ScriptError, ValueError) as exc:
                    raise Reject("puzzle-size", f"puzzle {ident}: {exc}") from exc
                if sides[-1].solve(int.from_bytes(SINGLE_BUG_DIGEST, "big")) is not None:
                    raise Reject("puzzle-size", f"puzzle {ident} accepts the SIGHASH_SINGLE bug digest")
            lo, hi = self.limits["testBitsMin"], self.limits["testBitsMax"]
            if not lo <= sides[1].bits <= hi:
                raise Reject("twin", f"puzzle {ident}: the test difficulty is {sides[1].bits:.2f} bits; "
                             f"the judge grinds between {lo} and {hi}")
            if sides[0].size - SIG_OVERHEAD > 32:
                raise Reject("puzzle-size", f"puzzle {ident}: the production size admits a 33-byte s")
            self.puzzles[ident] = Puzzle(ident, item["role"], key_at, size_at, sides[0], sides[1])
        self.pins = [p for p in self.puzzles.values() if p.role == "pin"]
        if len(self.pins) not in (0, PIN_PUZZLES):
            raise Reject("pin-cover", f"{len(self.pins)} pinning puzzles; the model credits pinning only to "
                         f"{PIN_PUZZLES} puzzles with disjoint targets, one per sighash mode (or none at all)")
        for side in ("prod", "test"):
            sets = [getattr(p, side).z_intervals() for p in self.pins]
            for i in range(len(sets)):
                for j in range(i):
                    if overlap(sets[i], sets[j]):
                        raise Reject("pin-cover", f"pinning puzzles {self.pins[j].id} and {self.pins[i].id} accept "
                                     f"a common sighash ({side}), so one signature mode could serve both")

    def _twin(self) -> None:
        allowed = bytearray(len(self.locking))
        for puzzle in self.puzzles.values():
            for offset in (puzzle.key_at, puzzle.size_at):
                start, end = self.data_span(offset)
                test_entry = self.ops_test.get(offset)
                if test_entry is None or test_entry[2] != end or test_entry[1] is None or end - len(test_entry[1]) != start:
                    raise Reject("twin", f"the push at offset {offset} has a different shape in the test script")
                allowed[start:end] = b"\x01" * (end - start)
        for i, (a, b) in enumerate(zip(self.locking, self.locking_test)):
            if a != b and not allowed[i]:
                raise Reject("twin", f"the test script differs from the production script at offset {i}, outside "
                             "the size and key pushes of the declared puzzles")

    # -- rounds --------------------------------------------------------------------------------

    def _rounds(self, items) -> None:
        if not isinstance(items, list) or not 1 <= len(items) <= self.limits["maxRounds"]:
            raise Reject("format", f"rounds must list 1 to {self.limits['maxRounds']} rounds")
        self.rounds: list[Round] = []
        pool_seen: dict[bytes, int] = {}
        commit_seen: set[bytes] = set()
        offsets_seen: set[int] = set()
        boundaries = sorted(self.ops)
        for number, item in enumerate(items):
            name = f"round {number}"
            _keys(item, name, {"puzzle", "t", "pool", "commit", "keys", "preimages"}, {"slots"})
            puzzle = self.puzzles.get(item["puzzle"]) if isinstance(item["puzzle"], str) else None
            if puzzle is None or puzzle.role != "round" or any(r.puzzle is puzzle for r in self.rounds):
                raise Reject("structure", f"{name}: needs a round puzzle of its own")
            lists = [item[k] for k in ("pool", "commit", "keys", "preimages")]
            if not all(isinstance(x, list) for x in lists) or len({len(x) for x in lists}) != 1:
                raise Reject("format", f"{name}: pool, commit, keys and preimages must be lists of one length")
            n = len(item["pool"])
            if not 1 <= n <= 1000:
                raise Reject("format", f"{name}: pool size out of range")
            t = _int(item["t"], f"{name} t", 1, min(n, S.MAX_MULTISIG_KEYS - 1))
            slots = item.get("slots", "any")
            if slots not in SLOT_ORDERS:
                raise Reject("format", f"{name}: slots must be one of {SLOT_ORDERS}")
            pool, commit = [], []
            width = None
            for j in range(n):
                p_at = _int(item["pool"][j], f"{name} pool[{j}]", 0, len(self.locking))
                c_at = _int(item["commit"][j], f"{name} commit[{j}]", 0, len(self.locking))
                if {p_at, c_at} & offsets_seen or p_at == c_at:
                    raise Reject("structure", f"{name}: element {j} reuses a push of another element")
                offsets_seen |= {p_at, c_at}
                sig, digest = self.push_at(p_at, f"{name} pool[{j}]"), self.push_at(c_at, f"{name} commit[{j}]")
                if not ec.is_strict_der(sig):
                    raise Reject("structure", f"{name}: pool element {j} is not a strictly encoded signature")
                width = len(sig) if width is None else width
                if len(sig) != width:
                    raise Reject("structure", f"{name}: pool elements must have one length")
                if sig in pool_seen:
                    raise Reject("nonce-space", f"{name}: pool element {j} repeats an element of round "
                                 f"{pool_seen[sig]}; pools must hold distinct signatures and must not overlap")
                pool_seen[sig] = number
                occurrences = sum(1 for b in boundaries if self.locking.startswith(S.push(sig), b))
                if occurrences != 1:
                    raise Reject("nonce-space", f"{name}: pool element {j} occurs {occurrences} times in the script")
                if len(digest) < self.limits["minCommitBytes"] or digest in commit_seen:
                    raise Reject("binding", f"{name}: commitment {j} is shorter than "
                                 f"{self.limits['minCommitBytes']} bytes or repeats another commitment")
                commit_seen.add(digest)
                pool.append(p_at)
                commit.append(c_at)
            keys = [_hex(k, f"{name} keys") for k in item["keys"]]
            preimages = [_hex(p, f"{name} preimages") for p in item["preimages"]]
            if any(len(p) < self.limits["minPreimageBytes"] or len(p) > S.MAX_ELEMENT_BYTES for p in preimages):
                raise Reject("binding", f"{name}: preimages must be {self.limits['minPreimageBytes']} to 520 bytes")
            if any(not 1 <= len(k) <= S.MAX_ELEMENT_BYTES for k in keys):
                raise Reject("format", f"{name}: keys must be 1 to 520 bytes")
            self.rounds.append(Round(puzzle, t, pool, commit, keys, preimages, slots))
        if {r.puzzle.id for r in self.rounds} != {p.id for p in self.puzzles.values() if p.role == "round"}:
            raise Reject("structure", "every round puzzle must belong to a round")

    # -- witness -------------------------------------------------------------------------------

    def _witness(self, items) -> None:
        if not isinstance(items, list) or not 1 <= len(items) <= S.MAX_STACK:
            raise Reject("format", "witness must be a non-empty list of items")
        self.witness: list[tuple] = []
        puzzles_seen: set[str] = set()
        slots_seen: dict[str, set] = {"index": set(), "key": set(), "pre": set()}
        for item in items:
            if not isinstance(item, dict) or not item:
                raise Reject("format", "a witness item must be an object")
            kind = next(k for k in ("puzzle", "index", "key", "pre", "push", None) if k is None or k in item)
            if kind == "puzzle":
                _keys(item, "witness puzzle item", {"puzzle"})
                if item["puzzle"] not in self.puzzles or item["puzzle"] in puzzles_seen:
                    raise Reject("format", "each puzzle signature appears once in the witness")
                puzzles_seen.add(item["puzzle"])
                self.witness.append(("puzzle", item["puzzle"]))
            elif kind in ("index", "key", "pre"):
                _keys(item, f"witness {kind} item", {kind}, {"enc", "mul", "add"} if kind == "index" else set())
                ref = item[kind]
                if not isinstance(ref, list) or len(ref) != 2:
                    raise Reject("format", f"witness {kind} item must name [round, slot]")
                r = _int(ref[0], "witness round", 0, len(self.rounds) - 1)
                slot = _int(ref[1], "witness slot", 0, self.rounds[r].t - 1)
                if (r, slot) in slots_seen[kind]:
                    raise Reject("format", f"witness {kind} [{r}, {slot}] appears twice")
                slots_seen[kind].add((r, slot))
                if kind == "index":
                    enc = item.get("enc", "rank")
                    if enc not in INDEX_ENCODINGS:
                        raise Reject("format", f"index encoding must be one of {INDEX_ENCODINGS}")
                    self.witness.append(("index", r, slot, enc, _int(item.get("add", 0), "index add", -100000, 100000),
                                         _int(item.get("mul", 1), "index mul", 1, 16)))
                else:
                    self.witness.append((kind, r, slot))
            elif kind == "push":
                _keys(item, "witness push item", {"push"})
                data = _hex(item["push"], "witness push")
                if len(data) > S.MAX_ELEMENT_BYTES:
                    raise Reject("format", "witness push larger than 520 bytes")
                self.witness.append(("push", data))
            else:
                raise Reject("format", "a witness item must be one of puzzle, index, key, pre, push")
        if puzzles_seen != set(self.puzzles):
            raise Reject("format", "every puzzle needs its signature in the witness")
        want = {(r, i) for r, rnd in enumerate(self.rounds) for i in range(rnd.t)}
        if slots_seen["index"] != want or slots_seen["pre"] != want:
            raise Reject("format", "every selected slot needs an index and a preimage in the witness")
        if slots_seen["key"] not in (want, set()):
            raise Reject("format", "witness keys must cover every slot or none")

    # -- unlocking script ----------------------------------------------------------------------

    def index_value(self, item: tuple, selection: list[int]) -> int:
        """The number an index item pushes: `mul` times the element's number (`abs`) or its
        position among the elements not chosen in earlier slots (`rank`), plus `add`."""
        _, _r, slot, enc, add, mul = item
        element = selection[slot]
        if enc == "rank":
            element -= sum(1 for earlier in selection[:slot] if earlier < element)
        return mul * element + add

    def unlocking(self, selections: list[list[int]], signatures: dict[str, bytes]) -> bytes:
        """The unlocking script for the given per-round selections and puzzle signatures."""
        out = bytearray()
        for item in self.witness:
            if item[0] == "puzzle":
                out += S.push(signatures[item[1]])
            elif item[0] == "index":
                out += S.push_num(self.index_value(item, selections[item[1]]))
            elif item[0] == "key":
                out += S.push(self.rounds[item[1]].keys[selections[item[1]][item[2]]])
            elif item[0] == "pre":
                out += S.push(self.rounds[item[1]].preimages[selections[item[1]][item[2]]])
            else:
                out += S.push(item[1])
        return bytes(out)

    def unlocking_bytes(self) -> int:
        """The largest unlocking script an honest production spend can need."""
        total = 0
        for item in self.witness:
            if item[0] == "puzzle":
                total += len(S.push(bytes(self.puzzles[item[1]].prod.size)))
            elif item[0] == "index":
                total += max(len(S.push_num(item[5] * v + item[4])) for v in range(self.rounds[item[1]].n))
            elif item[0] == "key":
                total += max(len(S.push(k)) for k in self.rounds[item[1]].keys)
            elif item[0] == "pre":
                total += max(len(S.push(p)) for p in self.rounds[item[1]].preimages)
            else:
                total += len(S.push(item[1]))
        return total

