"""secp256k1 and ECDSA as Bitcoin's legacy interpreter uses them. Standard library only.

This is the reference implementation the evaluator judges with: plain Jacobian arithmetic on
Python integers, written to be read. It is not constant time and must never hold a real key.
"""
from __future__ import annotations

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
INV2 = (N + 1) // 2

# The x-coordinate of (1/2)G: the shortest r with a known nonce (Binohash, section 2.1.3).
R_MIN = 0x3B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63


def lift_x(x: int, odd: bool) -> tuple[int, int] | None:
    if not 0 <= x < P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return (x, y if (y & 1) == odd else P - y)


def _double(pt):
    x, y, z = pt
    if not y or not z:
        return (0, 1, 0)
    s = 4 * x * y * y % P
    m = 3 * x * x % P
    nx = (m * m - 2 * s) % P
    return (nx, (m * (s - nx) - 8 * pow(y, 4, P)) % P, 2 * y * z % P)


def _add(a, b):
    if not a[2]:
        return b
    if not b[2]:
        return a
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1z1, z2z2 = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2z2 % P, x2 * z1z1 % P
    s1, s2 = y1 * z2 * z2z2 % P, y2 * z1 * z1z1 % P
    if u1 == u2:
        return _double(a) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3, v = h * h2 % P, u1 * h2 % P
    nx = (r * r - h3 - 2 * v) % P
    return (nx, (r * (v - nx) - s1 * h3) % P, h * z1 * z2 % P)


def _affine(pt):
    if not pt[2]:
        return None
    zi = pow(pt[2], -1, P)
    return (pt[0] * zi * zi % P, pt[1] * zi * zi * zi % P)


def mul(k: int, point=G):
    """k * point in affine coordinates; None is the point at infinity."""
    acc, add = (0, 1, 0), (point[0], point[1], 1)
    k %= N
    while k:
        if k & 1:
            acc = _add(acc, add)
        add = _double(add)
        k >>= 1
    return _affine(acc)


def mul2(a: int, b: int, point):
    """a * G + b * point (Shamir's trick)."""
    g, q = (GX, GY, 1), (point[0], point[1], 1)
    both = _add(g, q)
    acc = (0, 1, 0)
    for i in range(max(a.bit_length(), b.bit_length()) - 1, -1, -1):
        acc = _double(acc)
        bits = ((a >> i) & 1, (b >> i) & 1)
        if bits == (1, 1):
            acc = _add(acc, both)
        elif bits == (1, 0):
            acc = _add(acc, g)
        elif bits == (0, 1):
            acc = _add(acc, q)
    return _affine(acc)


def parse_pubkey(data: bytes):
    """A public key as consensus accepts it (compressed, uncompressed or hybrid), else None."""
    if len(data) == 33 and data[0] in (2, 3):
        return lift_x(int.from_bytes(data[1:], "big"), data[0] == 3)
    if len(data) == 65 and data[0] in (4, 6, 7):
        x, y = int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big")
        if x >= P or y >= P or (y * y - pow(x, 3, P) - 7) % P:
            return None
        if data[0] != 4 and (y & 1) != (data[0] == 7):
            return None
        return (x, y)
    return None


def compressed(point) -> bytes:
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def verify(point, z: int, r: int, s: int) -> bool:
    """ECDSA verification. High s is accepted, as consensus does for legacy scripts."""
    if point is None or not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    out = mul2(z * w % N, r * w % N, point)
    return out is not None and out[0] % N == r


def recover(r: int, s: int, z: int, odd: bool = False):
    """A public key under which (r, s) signs z, or None if r is not an x-coordinate."""
    nonce_point = lift_x(r, odd)
    if nonce_point is None or not (0 < r < N and 0 < s < N):
        return None
    ri = pow(r, -1, N)
    return mul2((-z * ri) % N, s * ri % N, nonce_point)


def is_strict_der(sig: bytes) -> bool:
    """BIP 66: `sig` is a strictly DER-encoded signature followed by one hash-type byte."""
    if len(sig) < 9 or len(sig) > 73 or sig[0] != 0x30 or sig[1] != len(sig) - 3:
        return False
    len_r = sig[3]
    if 5 + len_r >= len(sig):
        return False
    len_s = sig[5 + len_r]
    if len_r + len_s + 7 != len(sig):
        return False
    if sig[2] != 0x02 or len_r == 0 or sig[4] & 0x80:
        return False
    if len_r > 1 and sig[4] == 0 and not sig[5] & 0x80:
        return False
    if sig[len_r + 4] != 0x02 or len_s == 0 or sig[len_r + 6] & 0x80:
        return False
    if len_s > 1 and sig[len_r + 6] == 0 and not sig[len_r + 7] & 0x80:
        return False
    return True


def der_decode(sig: bytes) -> tuple[int, int]:
    """(r, s) of a strictly encoded signature with its hash-type byte."""
    len_r = sig[3]
    len_s = sig[5 + len_r]
    return int.from_bytes(sig[4:4 + len_r], "big"), int.from_bytes(sig[6 + len_r:6 + len_r + len_s], "big")


def der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return (b"\x00" + raw) if raw[0] & 0x80 else raw


def der_encode(r: int, s: int, hashtype: int) -> bytes:
    rb, sb = der_int(r), der_int(s)
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(body)]) + body + bytes([hashtype])
