"""The reference engine: Bitcoin's legacy script interpreter under today's consensus rules.

Rules applied to a bare (non-P2SH, non-witness) output: BIP 66 strict DER, BIP 147 NULLDUMMY,
the 10,000-byte, 201-operation, 520-byte-element and 1,000-item limits, FindAndDelete and
OP_CODESEPARATOR in the legacy signature hash. Relay policy (minimal pushes, low S, clean
stack, standard hash types) is not applied, because consensus does not apply it.

Two things are added for the judge and change no verdict:

- Provenance. Every stack item carries a tag: ("w", i) for the i-th push of the unlocking
  script, ("s", offset) for a push of the locking script, ("size", tag) for the result of
  OP_SIZE, ("h", opcode, tag) for a hash, ("eq", n) for the result of the n-th recorded
  equality, None for anything computed otherwise. Signature checks and equality checks are
  recorded with the tags of their operands; an equality is marked enforced when the script
  fails unless it holds (the VERIFY forms, or a result passed to OP_VERIFY).
- An oracle mode for the soundness audit. A signature check passes whenever the spender controls
  the signature or the public key, which is what a spender who grinds and recovers keys can
  arrange. A check whose signature and key are both constants of the locking script is still
  verified for real. An equality check passes when both operands come from the unlocking
  script (an item, its hash or its size), because the spender chooses both, and when a hash of
  an unlocking item is compared with a commitment the caller lists as openable, because the
  spender of an instance knows every preimage. Encoding rules always apply.
"""
from __future__ import annotations

import hashlib

from . import script as S
from . import secp256k1 as ec
from .tx import Tx, sighash

try:
    hashlib.new("ripemd160", b"")

    def ripemd160(data: bytes) -> bytes:
        return hashlib.new("ripemd160", data).digest()
except ValueError:  # OpenSSL without the legacy provider
    from .ripemd160 import ripemd160  # type: ignore[no-redef]

UNSUPPORTED = {S.OP_CHECKLOCKTIMEVERIFY, S.OP_CHECKSEQUENCEVERIFY}


def controlled(tag) -> bool:
    """The spender chooses this value: an unlocking item, or the hash or the size of one."""
    while tag is not None and tag[0] in ("h", "size"):
        tag = tag[-1]
    return tag is not None and tag[0] == "w"


class Trace:
    """What one execution did: recorded checks, executed operations, peak stack, failure reason."""

    def __init__(self):
        self.events: list[dict] = []
        self.ops = 0
        self.peak = 0
        self.error = ""


def _hash(opcode: int, data: bytes) -> bytes:
    if opcode == S.OP_RIPEMD160:
        return ripemd160(data)
    if opcode == S.OP_SHA1:
        return hashlib.sha1(data).digest()
    if opcode == S.OP_SHA256:
        return hashlib.sha256(data).digest()
    if opcode == S.OP_HASH160:
        return ripemd160(hashlib.sha256(data).digest())
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class _Machine:
    def __init__(self, tx: Tx, index: int, oracle: bool, trace: Trace, openable=frozenset()):
        self.tx, self.index, self.oracle, self.trace, self.openable = tx, index, oracle, trace, openable
        self.stack: list[tuple[bytes, object]] = []

    def satisfiable(self, a, b) -> bool:
        """An equality the spender can arrange whatever the honest values are."""
        if controlled(a) and controlled(b):
            return True
        return any(x in self.openable and y is not None and y[0] == "h" and controlled(y) for x, y in ((a, b), (b, a)))

    def check_sig(self, sig, key, code: bytes) -> bool:
        data, key_data = sig[0], key[0]
        if data and not ec.is_strict_der(data):
            raise S.ScriptError("signature is not strict DER")
        if not data:
            return False
        constant = lambda tag: tag is not None and tag[0] == "s"  # noqa: E731
        if self.oracle and not (constant(sig[1]) and constant(key[1])):
            return True
        point = ec.parse_pubkey(key_data)
        if point is None:
            return False
        r, s = ec.der_decode(data)
        z = int.from_bytes(sighash(self.tx, self.index, code, data[-1]), "big")
        return ec.verify(point, z, r, s)

    def eval(self, script: bytes, origin: str) -> None:
        if len(script) > S.MAX_SCRIPT_BYTES:
            raise S.ScriptError("script larger than 10,000 bytes")
        stack, alt, trace = self.stack, [], self.trace
        ops, code_start, executing, pushes = 0, 0, [], 0

        def pop():
            if not stack:
                raise S.ScriptError("stack underflow")
            return stack.pop()

        def number(item) -> int:
            return S.num_decode(item[0])

        for offset, opcode, data, _end in S.parse(script):
            live = all(executing)
            if data is not None:
                if len(data) > S.MAX_ELEMENT_BYTES:
                    raise S.ScriptError("push larger than 520 bytes")
                if live:
                    stack.append((data, (origin, pushes if origin == "w" else offset)))
                pushes += 1
            else:
                if opcode > S.OP_16:
                    ops += 1
                    if ops > S.MAX_OPS:
                        raise S.ScriptError("more than 201 operations")
                if opcode in S.DISABLED:
                    raise S.ScriptError(f"disabled opcode {S.NAMES.get(opcode, opcode)}")
                if opcode in UNSUPPORTED:
                    raise S.ScriptError(f"{S.NAMES[opcode]} is outside the evaluator's model")
                if opcode in (S.OP_IF, S.OP_NOTIF):
                    value = False
                    if live:
                        value = S.truthy(pop()[0]) ^ (opcode == S.OP_NOTIF)
                    executing.append(value)
                elif opcode == S.OP_ELSE:
                    if not executing:
                        raise S.ScriptError("unbalanced conditional")
                    executing[-1] = not executing[-1]
                elif opcode == S.OP_ENDIF:
                    if not executing:
                        raise S.ScriptError("unbalanced conditional")
                    executing.pop()
                elif opcode in (S.OP_VERIF, S.OP_VERNOTIF):
                    raise S.ScriptError("OP_VERIF")
                elif not live:
                    pass
                elif opcode == S.OP_1NEGATE or S.OP_1 <= opcode <= S.OP_16:
                    stack.append((S.num_encode(opcode - S.OP_1 + 1), (origin, pushes if origin == "w" else offset)))
                    pushes += 1
                elif opcode == S.OP_NOP or S.OP_NOP1 <= opcode <= S.OP_NOP10:
                    pass
                elif opcode == S.OP_VERIFY:
                    item = pop()
                    if not S.truthy(item[0]):
                        raise S.ScriptError("OP_VERIFY failed")
                    if item[1] is not None and item[1][0] == "eq":
                        trace.events[item[1][1]]["enforced"] = True
                elif opcode == S.OP_RETURN:
                    raise S.ScriptError("OP_RETURN")
                elif opcode == S.OP_TOALTSTACK:
                    alt.append(pop())
                elif opcode == S.OP_FROMALTSTACK:
                    if not alt:
                        raise S.ScriptError("alt stack underflow")
                    stack.append(alt.pop())
                elif opcode == S.OP_2DROP:
                    pop(), pop()
                elif opcode in (S.OP_2DUP, S.OP_3DUP):
                    k = 2 if opcode == S.OP_2DUP else 3
                    if len(stack) < k:
                        raise S.ScriptError("stack underflow")
                    stack.extend(stack[-k:])
                elif opcode == S.OP_2OVER:
                    if len(stack) < 4:
                        raise S.ScriptError("stack underflow")
                    stack.extend(stack[-4:-2])
                elif opcode == S.OP_2ROT:
                    if len(stack) < 6:
                        raise S.ScriptError("stack underflow")
                    moved = stack[-6:-4]
                    del stack[-6:-4]
                    stack.extend(moved)
                elif opcode == S.OP_2SWAP:
                    if len(stack) < 4:
                        raise S.ScriptError("stack underflow")
                    stack[-4:] = stack[-2:] + stack[-4:-2]
                elif opcode == S.OP_IFDUP:
                    if not stack:
                        raise S.ScriptError("stack underflow")
                    if S.truthy(stack[-1][0]):
                        stack.append(stack[-1])
                elif opcode == S.OP_DEPTH:
                    stack.append((S.num_encode(len(stack)), None))
                elif opcode == S.OP_DROP:
                    pop()
                elif opcode == S.OP_DUP:
                    if not stack:
                        raise S.ScriptError("stack underflow")
                    stack.append(stack[-1])
                elif opcode == S.OP_NIP:
                    if len(stack) < 2:
                        raise S.ScriptError("stack underflow")
                    del stack[-2]
                elif opcode == S.OP_OVER:
                    if len(stack) < 2:
                        raise S.ScriptError("stack underflow")
                    stack.append(stack[-2])
                elif opcode in (S.OP_PICK, S.OP_ROLL):
                    depth = number(pop())
                    if depth < 0 or depth >= len(stack):
                        raise S.ScriptError("pick or roll out of range")
                    item = stack[-depth - 1]
                    if opcode == S.OP_ROLL:
                        del stack[-depth - 1]
                    stack.append(item)
                elif opcode == S.OP_ROT:
                    if len(stack) < 3:
                        raise S.ScriptError("stack underflow")
                    stack.append(stack.pop(-3))
                elif opcode == S.OP_SWAP:
                    if len(stack) < 2:
                        raise S.ScriptError("stack underflow")
                    stack[-2], stack[-1] = stack[-1], stack[-2]
                elif opcode == S.OP_TUCK:
                    if len(stack) < 2:
                        raise S.ScriptError("stack underflow")
                    stack.insert(-2, stack[-1])
                elif opcode == S.OP_SIZE:
                    if not stack:
                        raise S.ScriptError("stack underflow")
                    stack.append((S.num_encode(len(stack[-1][0])), ("size", stack[-1][1])))
                elif opcode in (S.OP_EQUAL, S.OP_EQUALVERIFY):
                    b, a = pop(), pop()
                    ok = a[0] == b[0] or (self.oracle and self.satisfiable(a[1], b[1]))
                    trace.events.append({"op": "equal", "a": a[1], "b": b[1], "ok": ok,
                                         "enforced": opcode == S.OP_EQUALVERIFY})
                    if opcode == S.OP_EQUALVERIFY:
                        if not ok:
                            raise S.ScriptError("OP_EQUALVERIFY failed")
                    else:
                        stack.append((b"\x01" if ok else b"", ("eq", len(trace.events) - 1)))
                elif opcode in (S.OP_1ADD, S.OP_1SUB, S.OP_NEGATE, S.OP_ABS, S.OP_NOT, S.OP_0NOTEQUAL):
                    a = number(pop())
                    value = {S.OP_1ADD: a + 1, S.OP_1SUB: a - 1, S.OP_NEGATE: -a, S.OP_ABS: abs(a),
                             S.OP_NOT: int(a == 0), S.OP_0NOTEQUAL: int(a != 0)}[opcode]
                    stack.append((S.num_encode(value), None))
                elif S.OP_ADD <= opcode <= S.OP_MAX and opcode not in S.DISABLED:
                    right, left = pop(), pop()
                    b, a = number(right), number(left)
                    if opcode in (S.OP_NUMEQUAL, S.OP_NUMEQUALVERIFY):
                        if self.oracle and self.satisfiable(left[1], right[1]):
                            b = a
                        trace.events.append({"op": "equal", "a": left[1], "b": right[1], "ok": a == b,
                                             "enforced": opcode == S.OP_NUMEQUALVERIFY})
                    value = {
                        S.OP_ADD: a + b, S.OP_SUB: a - b, S.OP_BOOLAND: int(a != 0 and b != 0),
                        S.OP_BOOLOR: int(a != 0 or b != 0), S.OP_NUMEQUAL: int(a == b),
                        S.OP_NUMEQUALVERIFY: int(a == b), S.OP_NUMNOTEQUAL: int(a != b),
                        S.OP_LESSTHAN: int(a < b), S.OP_GREATERTHAN: int(a > b),
                        S.OP_LESSTHANOREQUAL: int(a <= b), S.OP_GREATERTHANOREQUAL: int(a >= b),
                        S.OP_MIN: min(a, b), S.OP_MAX: max(a, b),
                    }[opcode]
                    if opcode == S.OP_NUMEQUALVERIFY:
                        if not value:
                            raise S.ScriptError("OP_NUMEQUALVERIFY failed")
                    else:
                        tag = ("eq", len(trace.events) - 1) if opcode == S.OP_NUMEQUAL else None
                        stack.append((S.num_encode(value), tag))
                elif opcode == S.OP_WITHIN:
                    hi, lo, x = number(pop()), number(pop()), number(pop())
                    stack.append((S.num_encode(int(lo <= x < hi)), None))
                elif S.OP_RIPEMD160 <= opcode <= S.OP_HASH256:
                    item = pop()
                    stack.append((_hash(opcode, item[0]), ("h", opcode, item[1])))
                elif opcode == S.OP_CODESEPARATOR:
                    code_start = offset + 1
                elif opcode in (S.OP_CHECKSIG, S.OP_CHECKSIGVERIFY):
                    key, sig = pop(), pop()
                    code = S.find_and_delete(script[code_start:], S.push(sig[0]))
                    ok = self.check_sig(sig, key, code)
                    trace.events.append({"op": "checksig", "sig": sig, "key": key, "ok": ok, "code": code,
                                         "code_start": code_start, "origin": origin})
                    if opcode == S.OP_CHECKSIGVERIFY:
                        if not ok:
                            raise S.ScriptError("OP_CHECKSIGVERIFY failed")
                    else:
                        stack.append((b"\x01" if ok else b"", None))
                elif opcode in (S.OP_CHECKMULTISIG, S.OP_CHECKMULTISIGVERIFY):
                    n_keys = number(pop())
                    if not 0 <= n_keys <= S.MAX_MULTISIG_KEYS:
                        raise S.ScriptError("multisig key count out of range")
                    ops += n_keys
                    if ops > S.MAX_OPS:
                        raise S.ScriptError("more than 201 operations")
                    keys = [pop() for _ in range(n_keys)]
                    n_sigs = number(pop())
                    if not 0 <= n_sigs <= n_keys:
                        raise S.ScriptError("multisig signature count out of range")
                    sigs = [pop() for _ in range(n_sigs)]
                    dummy = pop()
                    code = script[code_start:]
                    for sig in sigs:
                        code = S.find_and_delete(code, S.push(sig[0]))
                    ok, i_sig, i_key = True, 0, 0
                    while ok and i_sig < n_sigs:
                        if self.check_sig(sigs[i_sig], keys[i_key], code):
                            i_sig += 1
                        i_key += 1
                        if n_sigs - i_sig > n_keys - i_key:
                            ok = False
                    if dummy[0]:
                        raise S.ScriptError("multisig dummy is not empty (BIP 147)")
                    trace.events.append({"op": "multisig", "sigs": sigs, "keys": keys, "ok": ok, "code": code,
                                         "code_start": code_start, "origin": origin})
                    if opcode == S.OP_CHECKMULTISIGVERIFY:
                        if not ok:
                            raise S.ScriptError("OP_CHECKMULTISIGVERIFY failed")
                    else:
                        stack.append((b"\x01" if ok else b"", None))
                else:
                    raise S.ScriptError(f"bad opcode 0x{opcode:02x}")
            if len(stack) + len(alt) > S.MAX_STACK:
                raise S.ScriptError("more than 1,000 stack items")
            trace.peak = max(trace.peak, len(stack) + len(alt))
        if executing:
            raise S.ScriptError("unbalanced conditional")
        if origin == "s":
            trace.ops = ops


def verify(script_sig: bytes, script_pubkey: bytes, tx: Tx, index: int, *, oracle: bool = False,
           trace: Trace | None = None, openable=frozenset()) -> bool:
    """Whether input `index` of `tx`, with this unlocking script, spends this locking script.

    `openable` is used in oracle mode only: the tags of locking-script pushes that are
    commitments whose preimages the spender knows."""
    trace = trace if trace is not None else Trace()
    machine = _Machine(tx, index, oracle, trace, openable)
    try:
        machine.eval(script_sig, "w")
        machine.eval(script_pubkey, "s")
    except S.ScriptError as exc:
        trace.error = str(exc)
        return False
    if not machine.stack or not S.truthy(machine.stack[-1][0]):
        trace.error = "the final stack is empty or its top is false"
        return False
    return True
