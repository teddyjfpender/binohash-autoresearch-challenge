"""What the evaluator counts: puzzle work, the security level and honest grinding work.

Everything here is exact integer or 50-digit decimal arithmetic, so the same instance gives the
same numbers on every machine. The definitions are spec/SECURITY-MODEL.md (BH-SEC-1) and
spec/WORK-MODEL.md (BH-WORK-1); this file is their implementation.
"""
from __future__ import annotations

import decimal
import itertools
import math
from decimal import Decimal

from .secp256k1 import INV2, N, R_MIN

CTX = decimal.Context(prec=50, rounding=decimal.ROUND_HALF_EVEN)
LN2 = CTX.ln(Decimal(2))
R_MIN_BYTES = 21  # DER length of R_MIN
SIG_OVERHEAD = 7 + R_MIN_BYTES  # tags, lengths and the hash-type byte around s


def log2(value) -> Decimal:
    return CTX.divide(CTX.ln(Decimal(value)), LN2)


def exp2(bits: Decimal) -> Decimal:
    return CTX.exp(CTX.multiply(bits, LN2))


def s_range(length: int) -> tuple[int, int] | None:
    """The values s whose DER integer is exactly `length` bytes, as [lo, hi), within [1, N)."""
    if length < 1:
        return None
    lo = 1 if length == 1 else 1 << (8 * length - 9)
    hi = min(1 << (8 * length - 1), N)
    return (lo, hi) if lo < hi else None


class SizePuzzle:
    """`OP_SIZE <size> OP_EQUALVERIFY <key> OP_CHECKSIG`: a signature of exactly `size` bytes.

    The key is d*G with d public. A signature that short must use the nonce point (1/2)G or its
    negation, whose x-coordinate R_MIN is the shortest known; then s = +-2(z + d*R_MIN) mod n is
    fixed by the sighash z. The puzzle accepts z when either s has the required length. Both
    signs and the reduction mod n are counted, because the interpreter accepts both.
    """

    def __init__(self, dlog: int, size: int):
        self.dlog, self.size = dlog % N, size
        self.offset = self.dlog * R_MIN % N
        span = s_range(size - SIG_OVERHEAD)
        if span is None or not 0 < self.dlog < N:
            raise ValueError("no signature with nonce R_MIN has this size under this key")
        lo, hi = span
        # u = 2(z + offset) mod n must be an s of the right length, or the negation of one.
        self.u_sets = _merge([(lo, hi), (N - hi + 1, N - lo + 1)])
        self.count = sum(b - a for a, b in self.u_sets)

    @property
    def bits(self) -> Decimal:
        """log2 of the expected number of sighashes tried per accepted one."""
        return log2(Decimal(N) / Decimal(self.count))

    def solve(self, z: int) -> tuple[int, int] | None:
        """(r, s) of a signature of the required size for sighash z, or None."""
        u = 2 * (z + self.offset) % N
        lo, hi = s_range(self.size - SIG_OVERHEAD)
        if lo <= u < hi:
            return R_MIN, u
        if lo <= N - u < hi:
            return R_MIN, N - u
        return None

    def z_intervals(self) -> list[tuple[int, int]]:
        """The accepted sighashes as disjoint intervals [a, b) of [0, n)."""
        out = []
        for a, b in self.u_sets:
            # u even: z = u/2 - offset; u odd: z = (u + n)/2 - offset.
            for start, stop, shift in (((a + 1) // 2, (b + 1) // 2, 0), (a // 2, b // 2, INV2)):
                if start < stop:
                    out += _wrap((start + shift - self.offset) % N, stop - start)
        return _merge(out)


def _wrap(start: int, length: int) -> list[tuple[int, int]]:
    if start + length <= N:
        return [(start, start + length)]
    return [(start, N), (0, start + length - N)]


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for a, b in sorted(i for i in intervals if i[0] < i[1]):
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def overlap(first: list[tuple[int, int]], second: list[tuple[int, int]]) -> bool:
    return any(a < d and c < b for a, b in first for c, d in second)


def _round_stats(rounds: list[tuple[int, Decimal]]) -> list[tuple[Decimal, Decimal, Decimal]]:
    """Per round: the puzzle's success probability q, the expected number of solutions lambda for
    one transaction, and the probability p that there is at least one."""
    out = []
    for space, bits in rounds:
        q = CTX.divide(Decimal(1), exp2(bits))
        lam = Decimal(space) * q
        out.append((q, lam, 1 - CTX.exp(-lam)))
    return out


def _staged(start: Decimal, stages: list[tuple[Decimal, Decimal]]) -> tuple[Decimal, tuple[int, ...]]:
    """The cheapest expected cost of a transaction whose rounds are tried one after another and
    abandoned at the first round without a solution: `stages` holds (cost, probability of going
    on) per round. Returns the cost and the order."""
    best, best_order = None, ()
    for order in itertools.permutations(range(len(stages))):
        reached, cost = Decimal(1), start
        for r in order:
            cost += reached * stages[r][0]
            reached *= stages[r][1]
        if best is None or cost < best:
            best, best_order = cost, order
    return best, best_order


def security_bits(pin_bits: Decimal | None, rounds: list[tuple[int, Decimal]]) -> Decimal:
    """BH-SEC-1 collision resistance in bits of sighash evaluations: the cheaper of two attacks.

    `rounds` holds (selections S_r, puzzle bits W_r); `pin_bits` is the cheapest pinning puzzle,
    or None when pinning is not credited. Both attackers abandon a transaction at the first
    round that has no solution for it.

    Exhaustive birthday. Pin T transactions and try every selection of every round. Two
    transactions share a solved selection of round r in an expected S_r * 4^-W_r ways, so a
    colliding pair appears at T = prod_r 2^W_r / sqrt(S_r). With S_r = 2^W_r and no abandoning
    this is the paper's section 5.3 figure.

    Stored digests. Find N digests by exhaustive or first-hit search, then test them on fresh
    pinned transactions: one evaluation per test, success 2^-sum(W_r) each. N is chosen to
    balance the pinning of the fresh transactions against the cost of the stored digests.
    Rounds with far more selections than their puzzle needs do not help against this attack.
    """
    pin = exp2(pin_bits) if pin_bits is not None else Decimal(0)
    stats = _round_stats(rounds)
    exhaustive, _ = _staged(pin, [(Decimal(space), p) for (space, _), (_, _, p) in zip(rounds, stats)])
    birthday = exhaustive
    for (space, bits), _ in zip(rounds, stats):
        birthday *= exp2(bits - log2(space) / 2)
    solvable = math.prod((p for _, _, p in stats), start=Decimal(1))
    first_hit, _ = _staged(pin, [(CTX.divide(p, q), p) for q, _, p in stats])
    per_digest = min(CTX.divide(first_hit, solvable),
                     CTX.divide(exhaustive, math.prod((lam for _, lam, _ in stats), start=Decimal(1))))
    tests = exp2(sum((bits for _, bits in rounds), Decimal(0)))
    stored = max(Decimal(1), CTX.sqrt(CTX.divide(tests * pin, per_digest)))
    targeted = CTX.divide(tests * pin, stored) + tests + stored * per_digest
    return log2(min(birthday, targeted))


def honest_work(pins: list[tuple[Decimal, int]], rounds: list[tuple[int, Decimal, int]]) -> dict:
    """BH-WORK-1 expected SHA-256 compressions for one honest spend.

    `pins` holds (puzzle bits, compressions per attempt) in the order of the reference grind,
    the SIGHASH_ALL puzzle last; `rounds` holds (selections, puzzle bits, compressions per
    attempt). A round with S selections of success probability q each has a solution with
    probability p = 1 - exp(-S q) and costs (p / q) attempts on average whether or not it has
    one. Rounds are independent, so the spender searches them in the cheapest order and stops
    at the first without a solution. Then only the SIGHASH_ALL puzzle is solved again: the
    spender changes a field no other pinning signature covers.
    """
    costs = [exp2(bits) * kappa for bits, kappa in pins]
    once, again = sum(costs[:-1], Decimal(0)), (costs[-1] if costs else Decimal(0))
    stats = _round_stats([(space, bits) for space, bits, _ in rounds])
    per_try, order = _staged(again, [(CTX.divide(p, q) * kappa, p) for (q, _, p), (_, _, kappa) in zip(stats, rounds)])
    solvable = math.prod((p for _, _, p in stats), start=Decimal(1))
    total = once + CTX.divide(per_try, solvable)
    pin_share = once + CTX.divide(again, solvable)
    return {
        "compressions": total,
        "bits": log2(total),
        "pin_bits": log2(pin_share) if pin_share else None,
        "rounds_solvable": solvable,
        "round_order": list(order),
        "expected_tries": CTX.divide(Decimal(1), solvable),
    }


def blocks(length: int) -> int:
    """SHA-256 compressions for a message of `length` bytes."""
    return (length + 9 + 63) // 64


def compressions(preimage_bytes: int, first_varying: int) -> int:
    """Compressions per attempt for a double SHA-256 whose first `first_varying` bytes are fixed:
    the blocks from the one that holds the first varying byte, plus one for the outer hash."""
    return blocks(preimage_bytes) - first_varying // 64 + 1


def choose(n: int, t: int) -> int:
    return math.comb(n, t)
