"""Bitcoin Script as bytes: opcodes, pushes, numbers, parsing and FindAndDelete."""
from __future__ import annotations

OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x00, 0x4C, 0x4D, 0x4E
OP_1NEGATE, OP_RESERVED, OP_1, OP_16 = 0x4F, 0x50, 0x51, 0x60
OP_NOP, OP_VER, OP_IF, OP_NOTIF, OP_VERIF, OP_VERNOTIF, OP_ELSE, OP_ENDIF = 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
OP_VERIFY, OP_RETURN = 0x69, 0x6A
OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP = range(0x6B, 0x73)
OP_IFDUP, OP_DEPTH, OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK = range(0x73, 0x7E)
OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_SIZE = 0x7E, 0x7F, 0x80, 0x81, 0x82
OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_EQUAL, OP_EQUALVERIFY, OP_RESERVED1, OP_RESERVED2 = range(0x83, 0x8B)
OP_1ADD, OP_1SUB, OP_2MUL, OP_2DIV, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL = range(0x8B, 0x93)
OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT = range(0x93, 0x9A)
OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL = range(0x9A, 0x9F)
OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX, OP_WITHIN = range(0x9F, 0xA6)
OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256, OP_CODESEPARATOR = range(0xA6, 0xAC)
OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY = range(0xAC, 0xB0)
OP_NOP1, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_NOP10 = 0xB0, 0xB1, 0xB2, 0xB9

DISABLED = {OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV,
            OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT}
NAMES = {value: name for name, value in dict(globals()).items() if name.startswith("OP_") and isinstance(value, int)}

MAX_SCRIPT_BYTES = 10_000
MAX_ELEMENT_BYTES = 520
MAX_OPS = 201
MAX_STACK = 1000
MAX_MULTISIG_KEYS = 20


class ScriptError(Exception):
    """The script is malformed or its execution fails."""


def push(data: bytes) -> bytes:
    """The push `CScript() << data` produces. FindAndDelete searches for exactly this encoding."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + n.to_bytes(2, "little") + data
    return bytes([OP_PUSHDATA4]) + n.to_bytes(4, "little") + data


def num_encode(value: int) -> bytes:
    """CScriptNum serialisation: little-endian magnitude with a sign bit."""
    if value == 0:
        return b""
    magnitude, out = abs(value), bytearray()
    while magnitude:
        out.append(magnitude & 0xFF)
        magnitude >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if value < 0 else 0x00)
    elif value < 0:
        out[-1] |= 0x80
    return bytes(out)


def num_decode(data: bytes, max_bytes: int = 4) -> int:
    """CScriptNum without the minimal-encoding rule, which is relay policy for legacy scripts."""
    if len(data) > max_bytes:
        raise ScriptError("script number overflow")
    if not data:
        return 0
    value = int.from_bytes(data, "little")
    if data[-1] & 0x80:
        return -(value & ~(0x80 << (8 * (len(data) - 1))))
    return value


def push_num(value: int) -> bytes:
    """The shortest push of a number: OP_0, OP_1NEGATE, OP_1..OP_16 or a data push."""
    if value == 0:
        return bytes([OP_0])
    if value == -1:
        return bytes([OP_1NEGATE])
    if 1 <= value <= 16:
        return bytes([OP_1 + value - 1])
    return push(num_encode(value))


def truthy(data: bytes) -> bool:
    for i, byte in enumerate(data):
        if byte:
            return not (i == len(data) - 1 and byte == 0x80)
    return False


def parse(script: bytes) -> list[tuple[int, int, bytes | None, int]]:
    """Every operation as (offset, opcode, pushed data or None, end offset). Raises on a truncated push."""
    ops, pc, end = [], 0, len(script)
    while pc < end:
        start, opcode = pc, script[pc]
        pc += 1
        data = None
        if opcode <= OP_PUSHDATA4:
            if opcode < OP_PUSHDATA1:
                size = opcode
            else:
                width = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[opcode]
                if pc + width > end:
                    raise ScriptError("truncated push length")
                size = int.from_bytes(script[pc:pc + width], "little")
                pc += width
            if pc + size > end:
                raise ScriptError("truncated push")
            data = script[pc:pc + size]
            pc += size
        ops.append((start, opcode, data, pc))
    return ops


def _next_op(script: bytes, pc: int) -> int | None:
    """Offset after the operation at `pc`, or None where CScript::GetOp fails."""
    end = len(script)
    if pc >= end:
        return None
    opcode = script[pc]
    pc += 1
    if opcode <= OP_PUSHDATA4:
        if opcode < OP_PUSHDATA1:
            size = opcode
        else:
            width = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[opcode]
            if pc + width > end:
                return None
            size = int.from_bytes(script[pc:pc + width], "little")
            pc += width
        if pc + size > end:
            return None
        pc += size
    return pc


def find_and_delete(script: bytes, needle: bytes) -> bytes:
    """Bitcoin Core's FindAndDelete: remove `needle` wherever it starts at an operation boundary."""
    if not needle:
        return script
    out, pc, kept, end, size = bytearray(), 0, 0, len(script), len(needle)
    while True:
        out += script[kept:pc]
        while end - pc >= size and script[pc:pc + size] == needle:
            pc += size
        kept = pc
        following = _next_op(script, pc)
        if following is None:
            break
        pc = following
    out += script[kept:end]
    return bytes(out)


def strip_codeseparators(script: bytes) -> bytes:
    """The scriptCode as the legacy signature hash serialises it: OP_CODESEPARATOR removed."""
    out, kept, pc = bytearray(), 0, 0
    while True:
        following = _next_op(script, pc)
        if following is None:
            break
        if script[pc] == OP_CODESEPARATOR:
            out += script[kept:pc]
            kept = following
        pc = following
    out += script[kept:]
    return bytes(out)
