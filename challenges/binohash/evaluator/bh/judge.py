"""The judge: static checks, seeded lanes, the soundness audit and the counted metrics.

A lane is one judge-chosen spending transaction. On every lane the judge grinds an honest spend
of the test twin itself, executes it with real signature verification, and checks from the
execution trace that the script made every check the instance declares. On audit lanes it then
plays a spender who may alter the unlocking script freely and can satisfy any signature check
whose signature or key they control, and requires every accepted execution to keep the declared
structure. spec/DESIGN.md describes each check and what it does and does not show.
"""
from __future__ import annotations

import hashlib
import hmac
from decimal import Decimal

from . import script as S
from . import secp256k1 as ec
from .instance import Instance, Reject
from .interp import Trace, _hash, verify
from .model import compressions, honest_work, log2, security_bits
from .tx import SINGLE_BUG_DIGEST, Tx, TxIn, TxOut, sighash, sighash_preimage, varint

INPUT = 1  # the Binohash input; input 0 precedes it so that one output triggers the SINGLE bug
ROUND_HASHTYPE = 0x01
# The reference grind (Binohash section 3.1.1): one sighash mode per pinning puzzle and, for
# each, a transaction field that the modes before it do not sign.
PIN_PLAN = ((0x82, "locktime"), (0x02, "input2-outpoint"), (0x81, "payload"), (0x01, "input2-sequence"))
GRIND_FACTOR = 64  # attempts allowed per puzzle, as a multiple of its expected count
LANE_RETRIES = 6


class Rng:
    """Deterministic bytes from the lane seed: HMAC-SHA256 in counter mode."""

    def __init__(self, seed: bytes, label: str):
        self.key, self.label, self.counter, self.buffer = seed, label.encode(), 0, b""

    def bytes(self, n: int) -> bytes:
        while len(self.buffer) < n:
            self.buffer += hmac.new(self.key, self.label + b"|" + self.counter.to_bytes(8, "big"), hashlib.sha256).digest()
            self.counter += 1
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out

    def below(self, n: int) -> int:
        size = (n.bit_length() + 7) // 8 + 1
        limit = (1 << (8 * size)) - ((1 << (8 * size)) % n)
        while True:
            value = int.from_bytes(self.bytes(size), "big")
            if value < limit:
                return value % n

    def sample(self, n: int, k: int) -> list[int]:
        """k distinct values below n, in random order."""
        pool = list(range(n))
        for i in range(k):
            j = i + self.below(n - i)
            pool[i], pool[j] = pool[j], pool[i]
        return pool[:k]


def reference_tx(rng: Rng, outputs: int = 1) -> Tx:
    """The transaction shape every lane uses: three inputs, the Binohash input second, and one
    OP_RETURN output, so the Binohash input's index is not below the number of outputs."""
    vin = [TxIn(rng.bytes(32), rng.below(4), b"", 0xFFFFFFFD) for _ in range(3)]
    vout = [TxOut(0, bytes([S.OP_RETURN, 32]) + rng.bytes(32)) for _ in range(outputs)]
    return Tx(2, vin, vout, rng.below(500_000_000))


def _mutate(tx: Tx, field: str, counter: int) -> None:
    if field == "locktime":
        tx.locktime = counter % 500_000_000
    elif field == "input2-outpoint":
        tx.vin[2].txid = counter.to_bytes(8, "little") + tx.vin[2].txid[8:]
    elif field == "payload":
        script = tx.vout[0].script
        tx.vout[0].script = script[:2] + counter.to_bytes(8, "little") + script[10:]
    else:
        tx.vin[2].sequence = counter & 0xFFFFFFFF


def _selection(rng: Rng, rnd) -> list[int]:
    chosen = rng.sample(rnd.n, rnd.t)
    if rnd.slots == "ascending":
        chosen.sort()
    elif rnd.slots == "descending":
        chosen.sort(reverse=True)
    return chosen


def _placeholder(size: int, hashtype: int) -> bytes:
    """A well-formed signature of the given size that signs nothing."""
    return ec.der_encode(ec.R_MIN, 1 << max(8 * (size - 28) - 2, 0), hashtype)


def _equalities(trace: Trace) -> set:
    pairs = set()
    for event in trace.events:
        if event["op"] == "equal" and event["ok"] and event["enforced"]:
            pairs.add((event["a"], event["b"]))
            pairs.add((event["b"], event["a"]))
    return pairs


def structure(inst: Instance, trace: Trace) -> dict:
    """What an accepted execution must have done, read from its trace. Raises ValueError with the
    missing check. Returns the selection each round used and the witness items it bound."""
    equal = _equalities(trace)
    sized = lambda tag, puzzle: (("size", tag), ("s", puzzle.size_at)) in equal  # noqa: E731
    found = {"pins": {}, "rounds": []}
    for puzzle in inst.pins:
        hits = [e for e in trace.events if e["op"] == "checksig" and e["key"][1] == ("s", puzzle.key_at)]
        good = [e for e in hits if e["ok"] and e["sig"][1] is not None and e["sig"][1][0] == "w" and sized(e["sig"][1], puzzle)]
        if not good:
            raise ValueError(f"pinning puzzle {puzzle.id}: no size-checked spender signature was verified under its key")
        found["pins"][puzzle.id] = good[0]
    for number, rnd in enumerate(inst.rounds):
        key_tag = ("s", rnd.puzzle.key_at)
        hits = [e for e in trace.events if e["op"] == "multisig" and any(k[1] == key_tag for k in e["keys"])]
        if len(hits) != 1 or not hits[0]["ok"]:
            raise ValueError(f"round {number}: its puzzle key is not used by exactly one passing OP_CHECKMULTISIG")
        event = hits[0]
        sigs, keys = event["sigs"], event["keys"]
        if len(sigs) != rnd.t + 1 or len(keys) != rnd.t + 1:
            raise ValueError(f"round {number}: the multisig checks {len(sigs)} signatures against {len(keys)} keys, "
                             f"not {rnd.t + 1} against {rnd.t + 1}")
        position = next(i for i, k in enumerate(keys) if k[1] == key_tag)
        puzzle_sig = sigs[position]
        if puzzle_sig[1] is None or puzzle_sig[1][0] != "w" or not sized(puzzle_sig[1], rnd.puzzle):
            raise ValueError(f"round {number}: the signature checked under the puzzle key is not a size-checked "
                             "spender signature")
        by_offset = {offset: j for j, offset in enumerate(rnd.pool)}
        chosen, bound = [], {}
        for i, sig in enumerate(sigs):
            if i == position:
                continue
            tag = sig[1]
            if tag is None or tag[0] != "s" or tag[1] not in by_offset:
                raise ValueError(f"round {number}: a signature that is not an element of the round's pool reached "
                                 "the multisig")
            element = by_offset[tag[1]]
            if element in chosen:
                raise ValueError(f"round {number}: pool element {element} is selected twice")
            commit_tag = ("s", rnd.commit[element])
            opening = [a for a, b in equal if b == commit_tag and a is not None and a[0] == "h"
                       and a[2] is not None and a[2][0] == "w"]
            if not opening:
                raise ValueError(f"round {number}: element {element} is selected without a revealed preimage of its "
                                 "commitment")
            chosen.append(element)
            bound[element] = opening[0]
        found["rounds"].append({"event": event, "puzzle_sig": puzzle_sig[1], "chosen": chosen, "bound": bound})
    return found


class Judge:
    def __init__(self, raw: bytes, spec: dict, seed: bytes):
        self.spec, self.seed = spec, seed
        self.inst = Instance(raw, spec["limits"])
        self.digest = hashlib.sha256(raw).hexdigest()
        self.vectors: list[tuple[str, bytes, bytes, bool]] = []
        self.counts = {"lanes": 0, "honest_spends": 0, "selections_probed": 0, "mutants": 0, "mutants_accepted": 0,
                       "audit_lanes": 0, "table_entries": 0, "core_vectors": 0}
        self.metrics: dict = {}
        self.ops = self.peak = None
        self.hash_ops: dict[int, int] = {}

    # -- building spends -----------------------------------------------------------------------

    def items(self, selections, signatures) -> list[bytes]:
        """The unlocking script as a list of stack items."""
        out = []
        for item in self.inst.witness:
            if item[0] == "puzzle":
                out.append(signatures[item[1]])
            elif item[0] == "index":
                out.append(S.num_encode(self.inst.index_value(item, selections[item[1]])))
            elif item[0] == "key":
                out.append(self.inst.rounds[item[1]].keys[selections[item[1]][item[2]]])
            elif item[0] == "pre":
                out.append(self.inst.rounds[item[1]].preimages[selections[item[1]][item[2]]])
            else:
                out.append(item[1])
        return out

    def placeholders(self) -> dict[str, bytes]:
        return {p.id: _placeholder(p.test.size, 0x01) for p in self.inst.puzzles.values()}

    def probe(self, tx: Tx, selections) -> tuple[Trace, dict]:
        """An oracle execution with placeholder puzzle signatures: the script's data flow for these
        selections, which tells the grinder what each puzzle signature has to sign."""
        trace = Trace()
        script_sig = self.inst.unlocking(selections, self.placeholders())
        if not verify(script_sig, self.inst.locking_test, tx, INPUT, oracle=True, trace=trace):
            raise Reject("honest-spend", f"the declared witness does not execute for a sampled selection ({trace.error})")
        try:
            found = structure(self.inst, trace)
        except ValueError as exc:
            raise Reject("structure", str(exc)) from exc
        for r, rnd in enumerate(self.inst.rounds):
            if sorted(found["rounds"][r]["chosen"]) != sorted(selections[r]):
                raise Reject("nonce-space", f"round {r}: the witness for selection {sorted(selections[r])} selects "
                             f"{sorted(found['rounds'][r]['chosen'])}")
        return trace, found

    def grind(self, rng: Rng, tx: Tx) -> tuple[list[list[int]], dict[str, bytes]] | None:
        """An honest spend of the test twin for `tx` (which is modified in place), or None when a
        round has no solution for the pinned transaction."""
        inst = self.inst
        selections = [_selection(rng, rnd) for rnd in inst.rounds]
        _trace, found = self.probe(tx, selections)
        signatures = {}
        for puzzle, (hashtype, field) in zip(inst.pins, PIN_PLAN):
            code = found["pins"][puzzle.id]["code"]
            start = rng.below(1 << 30)
            for attempt in range(GRIND_FACTOR << int(puzzle.test.bits + 1)):
                _mutate(tx, field, start + attempt)
                solved = puzzle.test.solve(int.from_bytes(sighash(tx, INPUT, code, hashtype), "big"))
                if solved:
                    signatures[puzzle.id] = ec.der_encode(*solved, hashtype)
                    break
            else:
                raise Reject("honest-spend", f"pinning puzzle {puzzle.id}: no solution in {GRIND_FACTOR}x the expected attempts")
        for r, rnd in enumerate(inst.rounds):
            base = inst.locking_test[found["rounds"][r]["event"]["code_start"]:]
            budget = min(GRIND_FACTOR << int(rnd.puzzle.test.bits + 1), 8 * rnd.selections)
            for _ in range(budget):
                candidate = _selection(rng, rnd)
                code = base
                for element in candidate:
                    code = S.find_and_delete(code, S.push(inst.push_at(rnd.pool[element], "pool")))
                solved = rnd.puzzle.test.solve(int.from_bytes(sighash(tx, INPUT, code, ROUND_HASHTYPE), "big"))
                if solved:
                    selections[r] = candidate
                    signatures[rnd.puzzle.id] = ec.der_encode(*solved, ROUND_HASHTYPE)
                    break
            else:
                return None
        return selections, signatures

    # -- lanes ---------------------------------------------------------------------------------

    def lane(self, number: int, audit: bool, vectors: bool) -> None:
        inst = self.inst
        rng = Rng(self.seed, f"lane-{number}")
        self.nonce_space(number, Rng(self.seed, f"selections-{number}"), reference_tx(rng))
        for _ in range(LANE_RETRIES):
            tx = reference_tx(rng)
            spend = self.grind(rng, tx)
            if spend is not None:
                break
        else:
            raise Reject("honest-spend", f"lane {number}: no honest spend of the test twin in {LANE_RETRIES} pinned transactions")
        selections, signatures = spend
        script_sig = inst.unlocking(selections, signatures)
        trace = Trace()
        if not verify(script_sig, inst.locking_test, tx, INPUT, trace=trace):
            raise Reject("honest-spend", f"lane {number}: the honest spend is refused ({trace.error})")
        self.strict(number, trace, selections)
        if verify(script_sig, inst.locking, tx, INPUT):
            raise Reject("twin", f"lane {number}: the production script accepts a spend ground at the test difficulty")
        if self.ops not in (None, trace.ops):
            raise Reject("straight-line", "the executed operation count differs between lanes")
        self.ops, self.peak = trace.ops, max(self.peak or 0, trace.peak)
        self.counts["lanes"] += 1
        self.counts["honest_spends"] += 1
        if vectors:
            self.vector(f"lane{number}-honest", tx, script_sig, True)
        self.bug_forced(number, rng, tx, selections, signatures)
        if audit:
            self.audit(number, rng, tx, selections, signatures, trace.peak, vectors)

    def strict(self, number: int, trace: Trace, selections) -> None:
        """The honest execution used exactly the witness items the instance declares."""
        inst = self.inst
        try:
            found = structure(inst, trace)
        except ValueError as exc:
            raise Reject("structure", f"lane {number}: {exc}") from exc
        position = {}
        for i, item in enumerate(inst.witness):
            position[item[:3] if item[0] != "puzzle" else item] = i
        for puzzle in inst.pins:
            if found["pins"][puzzle.id]["sig"][1] != ("w", position[("puzzle", puzzle.id)]):
                raise Reject("structure", f"lane {number}: pinning puzzle {puzzle.id} checks another witness item")
        for r, rnd in enumerate(inst.rounds):
            got = found["rounds"][r]
            if got["puzzle_sig"] != ("w", position[("puzzle", rnd.puzzle.id)]) or sorted(got["chosen"]) != sorted(selections[r]):
                raise Reject("structure", f"lane {number}: round {r} does not check its declared signature and selection")
            for slot, element in enumerate(selections[r]):
                opening = got["bound"][element]
                if opening[2] != ("w", position[("pre", r, slot)]):
                    raise Reject("binding", f"lane {number}: round {r} slot {slot} is bound by another witness item")
                if self.hash_ops.setdefault(r, opening[1]) != opening[1]:
                    raise Reject("binding", f"round {r} opens its commitments with more than one hash")
        # A signature in the script that no pool declares would be a selection the count misses.
        declared = {offset for rnd in inst.rounds for offset in rnd.pool}
        fixed = {e["sig"][1][1] for e in trace.events if e["op"] == "checksig" and e["ok"]
                 and all(x[1] is not None and x[1][0] == "s" for x in (e["sig"], e["key"]))}
        for offset, (_opcode, data, _end) in inst.ops.items():
            if data is not None and ec.is_strict_der(data) and offset not in declared | fixed:
                raise Reject("nonce-space", f"the push at offset {offset} is a signature that no pool declares and no "
                             "check against a constant key consumes; an undeclared pool element is a selection the "
                             "security count does not see")

    def nonce_space(self, number: int, rng: Rng, tx: Tx) -> None:
        """Sampled selections all execute, select what they say and give distinct sighashes."""
        inst = self.inst
        probes = self.spec["validation"]["selectionsPerLane"]
        seen: dict[bytes, tuple] = {}
        for k in range(probes):
            selections = [_selection(rng, rnd) for rnd in inst.rounds]
            if number == 0 and k < 2:  # the two ends of every pool
                selections = [sorted(range(rnd.t) if k == 0 else range(rnd.n - rnd.t, rnd.n),
                                     reverse=rnd.slots == "descending") for rnd in inst.rounds]
            _trace, found = self.probe(tx, selections)
            for r, rnd in enumerate(inst.rounds):
                event = found["rounds"][r]["event"]
                missing = [e for e in selections[r] if rnd.pool[e] < event["code_start"]]
                if missing:
                    raise Reject("nonce-space", f"round {r}: pool element {missing[0]} lies before the scriptCode "
                                 "its multisig signs, so selecting it does not change the sighash")
                digest = sighash(tx, INPUT, event["code"], ROUND_HASHTYPE)
                key = (r, frozenset(selections[r]))
                if seen.setdefault(digest, key) != key:
                    raise Reject("nonce-space", f"round {r}: two different selections give the same sighash")
            self.counts["selections_probed"] += 1

    def bug_forced(self, number: int, rng: Rng, tx: Tx, selections, signatures) -> None:
        """With an output at the input's index the SIGHASH_SINGLE bug is off; no spend may pass."""
        other = tx.copy()
        other.vout.append(TxOut(0, bytes([S.OP_RETURN, 32]) + rng.bytes(32)))
        script_sig = self.inst.unlocking(selections, signatures)
        if verify(script_sig, self.inst.locking_test, other, INPUT, oracle=True):
            raise Reject("single-bug", f"lane {number}: the script accepts a transaction that does not trigger the "
                         "SIGHASH_SINGLE bug, so SIGHASH_SINGLE signatures are not excluded from the pinning puzzles")

    # -- the soundness audit -------------------------------------------------------------------

    def audit(self, number: int, rng: Rng, tx: Tx, selections, signatures, peak: int, vectors: bool) -> None:
        inst = self.inst
        honest = self.items(selections, signatures)
        kinds = [item[0] for item in inst.witness]
        indexes = [i for i, k in enumerate(kinds) if k == "index"]
        validation = self.spec["validation"]
        # The spender of an instance made its commitments, so they can open any of them.
        openable = frozenset(("s", offset) for rnd in inst.rounds for offset in rnd.commit)

        def attempt(items: list[bytes], what: str) -> None:
            if any(len(i) > S.MAX_ELEMENT_BYTES for i in items):
                return
            script_sig = b"".join(S.push(i) for i in items)
            trace = Trace()
            self.counts["mutants"] += 1
            if not verify(script_sig, inst.locking_test, tx, INPUT, oracle=True, trace=trace, openable=openable):
                return
            self.counts["mutants_accepted"] += 1
            try:
                structure(inst, trace)
            except ValueError as exc:
                raise Reject("soundness", f"lane {number}: a spender who {what} is accepted although {exc}; "
                             f"unlocking items {[i.hex() for i in items]}") from exc

        def swapped(i: int, value: bytes) -> list[bytes]:
            return honest[:i] + [value] + honest[i + 1:]

        # Every value an index can take, one index at a time.
        for i in indexes:
            for value in range(-2, peak + 3):
                attempt(swapped(i, S.num_encode(value)), f"sets witness item {i} to {value}")
        # Several indexes at once.
        for _ in range(validation["multiSlotMutants"]):
            items = list(honest)
            for i in rng.sample(len(indexes), min(len(indexes), 2 + rng.below(3))):
                items[indexes[i]] = S.num_encode(rng.below(peak + 3) - 1)
            attempt(items, "changes several indexes")
        # Three or four items of any kind at once: an index takes another value, anything else is
        # replaced by a copy of another item. A missing check may need its neighbours moved too.
        for _ in range(validation["multiSlotMutants"] if len(honest) > 3 else 0):
            items = list(honest)
            for i in rng.sample(len(honest), 3 + rng.below(2)):
                items[i] = S.num_encode(rng.below(peak + 3) - 1) if kinds[i] == "index" else honest[rng.below(len(honest))]
            attempt(items, "alters several witness items")
        # Items exchanged, dropped, repeated.
        for _ in range(validation["swapMutants"]):
            a, b = rng.sample(len(honest), 2) if len(honest) > 1 else (0, 0)
            items = list(honest)
            items[a], items[b] = items[b], items[a]
            attempt(items, f"exchanges witness items {a} and {b}")
        for i in range(len(honest)):
            attempt(honest[:i] + honest[i + 1:], f"drops witness item {i}")
            attempt(honest[:i] + [honest[i]] + honest[i:], f"repeats witness item {i}")
        # Preimages and keys the spender does not hold, and puzzle signatures of the wrong kind.
        for i, item in enumerate(inst.witness):
            if item[0] == "pre":
                rnd = inst.rounds[item[1]]
                attempt(swapped(i, rng.bytes(len(honest[i]))), f"replaces the preimage in witness item {i} by random bytes")
                attempt(swapped(i, rnd.preimages[rng.below(rnd.n)]), f"opens witness item {i} with another element's preimage")
                attempt(swapped(i, b""), f"empties the preimage in witness item {i}")
            elif item[0] == "key":
                attempt(swapped(i, ec.compressed(ec.mul(1 + rng.below(1 << 64)))), f"replaces the key in witness item {i}")
            elif item[0] == "puzzle":
                puzzle = inst.puzzles[item[1]]
                attempt(swapped(i, _placeholder(puzzle.test.size, 0x82)), f"signs witness item {i} with SIGHASH_NONE|ANYONECANPAY")
                attempt(swapped(i, _placeholder(puzzle.test.size - 1, 0x01)), f"shortens the signature in witness item {i}")
                attempt(swapped(i, _placeholder(puzzle.test.size + 1, 0x01)), f"lengthens the signature in witness item {i}")
                attempt(swapped(i, inst.push_at(inst.rounds[0].pool[0], "pool")), f"puts a pool signature in witness item {i}")
                attempt(swapped(i, b""), f"empties the signature in witness item {i}")
        # Items planted beneath the honest ones, for an index that reaches past its pool.
        # The pad is deeper than any pool, so a signature and its commitment can both come from it.
        # Planted signatures are the shortest there are, so the pad fits the 10,000-byte limit of an
        # unlocking script even under the largest pools.
        plant = bytes.fromhex("300602010102010101")
        room = (S.MAX_SCRIPT_BYTES - sum(len(S.push(i)) for i in honest) - 8) // len(S.push(plant))
        depth = max(0, min(max(rnd.n for rnd in inst.rounds) + validation["plantedMargin"], S.MAX_STACK - peak - 1, room))
        for i in indexes:
            for value in range(peak + depth + 2):
                attempt([plant] * depth + swapped(i, S.num_encode(value)), f"plants {depth} signatures under the witness and sets item {depth + i} to {value}")
        for _ in range(validation["multiSlotMutants"] if depth else 0):
            items = list(honest)
            for i in rng.sample(len(indexes), min(len(indexes), 2 + rng.below(3))):
                items[indexes[i]] = S.num_encode(rng.below(peak + depth + 2))
            attempt([plant] * depth + items, f"plants {depth} signatures under the witness and changes several indexes")
        # A puzzle signature of the right size that signs nothing: refused for real, not only in the oracle.
        for i, item in enumerate(inst.witness):
            if item[0] == "puzzle":
                forged = swapped(i, _placeholder(inst.puzzles[item[1]].test.size, 0x01))
                self.counts["mutants"] += 1
                if verify(b"".join(S.push(x) for x in forged), inst.locking_test, tx, INPUT):
                    raise Reject("soundness", f"lane {number}: puzzle {item[1]} accepts a signature that does not verify")
        self.counts["audit_lanes"] += 1
        if vectors:
            # The same alterations with real signature verification, for the comparison with Core.
            first_pre = next(i for i, k in enumerate(kinds) if k == "pre")
            negatives = {
                "wrong-preimage": swapped(first_pre, rng.bytes(len(honest[first_pre]))),
                "other-index": swapped(indexes[0], S.num_encode(S.num_decode(honest[indexes[0]]) + 1)),
                "dropped-item": honest[1:],
            }
            for name, items in negatives.items():
                script_sig = b"".join(S.push(i) for i in items)
                self.vector(f"lane{number}-{name}", tx, script_sig, verify(script_sig, inst.locking_test, tx, INPUT))
            other = tx.copy()
            other.vout.append(TxOut(0, bytes([S.OP_RETURN])))
            script_sig = inst.unlocking(selections, signatures)
            self.vector(f"lane{number}-no-single-bug", other, script_sig, verify(script_sig, inst.locking_test, other, INPUT))

    def vector(self, name: str, tx: Tx, script_sig: bytes, verdict: bool) -> None:
        spend = tx.copy()
        spend.vin[INPUT].script_sig = script_sig
        self.vectors.append((name, self.inst.locking_test, spend.serialize(), verdict))
        self.counts["core_vectors"] += 1

    # -- deterministic coverage of the tables --------------------------------------------------

    def tables(self) -> None:
        """Every pool element, not only the sampled ones: its preimage opens its commitment, and
        where the witness supplies keys its key verifies its signature."""
        inst = self.inst
        z_bug = int.from_bytes(SINGLE_BUG_DIGEST, "big")
        with_keys = any(item[0] == "key" for item in inst.witness)
        for r, rnd in enumerate(inst.rounds):
            for j in range(rnd.n):
                commitment = inst.push_at(rnd.commit[j], "commit")
                if _hash(self.hash_ops[r], rnd.preimages[j]) != commitment:
                    raise Reject("binding", f"round {r}: the preimage of element {j} does not open its commitment")
                sig = inst.push_at(rnd.pool[j], "pool")
                if with_keys and sig[-1] & 0x1F == 3:
                    if not ec.verify(ec.parse_pubkey(rnd.keys[j]), z_bug, *ec.der_decode(sig)):
                        raise Reject("nonce-space", f"round {r}: the key of element {j} does not verify its signature")
                self.counts["table_entries"] += 1

    # -- counting ------------------------------------------------------------------------------

    def count(self) -> None:
        inst = self.inst
        rng = Rng(b"\x00" * 32, "count")  # any transaction of the reference shape gives the same lengths
        tx = reference_tx(rng)
        selections = [sorted(range(rnd.t), reverse=rnd.slots == "descending") for rnd in inst.rounds]
        trace = Trace()
        verify(inst.unlocking(selections, self.placeholders()), inst.locking_test, tx, INPUT, oracle=True, trace=trace)
        found = structure(inst, trace)
        pins, pin_rows = [], []
        for puzzle, (hashtype, field) in zip(inst.pins, PIN_PLAN):
            # The production script has the test script's layout, so its scriptCode starts at the same offset.
            code = inst.locking[found["pins"][puzzle.id]["code_start"]:]
            before, after = tx.copy(), tx.copy()
            _mutate(before, field, 0)
            _mutate(after, field, 1)
            a, b = sighash_preimage(before, INPUT, code, hashtype), sighash_preimage(after, INPUT, code, hashtype)
            first = next(i for i in range(len(a)) if a[i] != b[i])
            kappa = compressions(len(a), first)
            pins.append((puzzle.prod.bits, kappa))
            pin_rows.append({"id": puzzle.id, "bits": puzzle.prod.bits, "size": puzzle.prod.size, "hashtype": hashtype,
                             "grind": field, "compressions": kappa, "preimage_bytes": len(a)})
        rounds, round_rows = [], []
        for r, rnd in enumerate(inst.rounds):
            event = found["rounds"][r]["event"]
            start = event["code_start"]
            whole = sighash_preimage(tx, INPUT, inst.locking[start:], ROUND_HASHTYPE)
            width = len(S.push(inst.push_at(rnd.pool[0], "pool")))
            removed = len(whole) - len(sighash_preimage(tx, INPUT, event["code"], ROUND_HASHTYPE))
            if removed != rnd.t * width:
                raise Reject("nonce-space", f"round {r}: selecting {rnd.t} elements removes {removed} bytes, not {rnd.t * width}")
            code = S.strip_codeseparators(inst.locking[start:])
            prefix = 4 + 1 + (36 + 1 + 4) * INPUT + 36 + len(varint(len(code) - removed))
            # Offsets of the pool pushes in the serialised scriptCode, in script order.
            offsets = sorted(len(S.strip_codeseparators(inst.locking[start:p])) for p in rnd.pool)
            innermost = -(-rnd.t * (rnd.n + 1) // (rnd.t + 1))  # the expected largest of t ranks out of n
            first = prefix + offsets[min(innermost, rnd.n) - 1] - (rnd.t - 1) * width
            kappa = compressions(len(whole) - removed, first)
            rounds.append((rnd.selections, rnd.puzzle.prod.bits, kappa))
            round_rows.append({"puzzle": rnd.puzzle.id, "n": rnd.n, "t": rnd.t, "selection_bits": log2(rnd.selections),
                               "bits": rnd.puzzle.prod.bits, "size": rnd.puzzle.prod.size, "compressions": kappa,
                               "preimage_bytes": len(whole) - removed, "first_varying_byte": first,
                               "expected_solutions": Decimal(rnd.selections) / (Decimal(ec.N) / rnd.puzzle.prod.count)})
        pin_bits = min(p.prod.bits for p in inst.pins) if inst.pins else None
        if pins:
            # The spender gives SIGHASH_ALL, the mode a retry repeats, to the cheapest puzzle.
            cheapest = min(range(len(pins)), key=lambda i: (pins[i][0], -i))
            kappas = [kappa for _, kappa in pins]
            order = [i for i in range(len(pins)) if i != cheapest] + [cheapest]
            pins = [(pins[i][0], kappas[position]) for position, i in enumerate(order)]
        work = honest_work(pins, rounds)
        locking, unlocking = len(inst.locking), inst.unlocking_bytes()
        if unlocking > S.MAX_SCRIPT_BYTES:
            raise Reject("limits", f"the unlocking script needs {unlocking} bytes; consensus allows {S.MAX_SCRIPT_BYTES}")
        self.metrics = {
            "bytes": locking + unlocking, "locking_bytes": locking, "unlocking_bytes": unlocking,
            "opcodes": self.ops, "stack_peak": self.peak, "work_bits": work["bits"],
            "security_bits": security_bits([p.prod.bits for p in inst.pins] if inst.pins else None,
                                           [(space, bits) for space, bits, _ in rounds]),
            "pin_bits": pin_bits, "pins": pin_rows, "rounds": round_rows,
            "work": {k: v for k, v in work.items() if k != "bits"},
        }

    def run(self, lanes: int, audit_lanes: int, vector_lanes: int) -> None:
        for number in range(lanes):
            self.lane(number, audit=number < audit_lanes, vectors=number < vector_lanes)
        self.tables()
        self.count()
        floor = Decimal(self.spec["floorBits"])
        if self.metrics["security_bits"] < floor:
            raise Reject("security-floor", f"{self.metrics['security_bits']:.3f} bits under {self.spec['model']}; "
                         f"the track requires {floor}")
        if self.metrics["opcodes"] > S.MAX_OPS:
            raise Reject("limits", "more than 201 operations")
