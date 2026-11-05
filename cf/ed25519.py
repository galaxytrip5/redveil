# language: Python 3.11+, file: cf/ed25519.py
# *pure-Python Ed25519 (RFC 8032) — stdlib only, license signing surface*
from __future__ import annotations

import hashlib
import os

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, P - 2, P)) % P
_IDENTITY = (0, 1, 1, 0)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _recover_x(y: int, sign_bit: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % P
    if x2 == 0:
        return None if sign_bit else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign_bit:
        x = P - x
    return x


# extended coordinates — each point is (X, Y, Z, T) with x=X/Z, y=Y/Z, T=XY/Z

def _point_add(p: tuple[int, int, int, int],
               q: tuple[int, int, int, int],
               ) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * _D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(scalar: int, p: tuple[int, int, int, int]
               ) -> tuple[int, int, int, int]:
    q = _IDENTITY
    while scalar > 0:
        if scalar & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        scalar >>= 1
    return q


def _point_equal(p: tuple[int, int, int, int],
                 q: tuple[int, int, int, int]) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % P != 0:
        return False
    if (p[1] * q[2] - q[1] * p[2]) % P != 0:
        return False
    return True


_BY = 4 * _inv(5) % P
# RFC 8032 base point Bx is even (…170) — pick the even root
_BX = _recover_x(_BY, 0)
assert _BX is not None
_B = (_BX, _BY, 1, _BX * _BY % P)


def _point_compress(p: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    zinv = _inv(z)
    x = x * zinv % P
    y = y * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes) -> tuple[int, int, int, int] | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign_bit = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign_bit)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _scalar(seed: bytes) -> int:
    """Clamped scalar a from the 32-byte seed — [a]B == public_key(seed)."""
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    h = _sha512(seed)[:32]
    a = bytearray(h)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little")


def public_key(seed: bytes) -> bytes:
    """32-byte public key derived from the private seed."""
    return _point_compress(_point_mul(_scalar(seed), _B))


def sign(seed: bytes, message: bytes) -> bytes:
    """Deterministic RFC 8032 sign — same seed+message, same signature."""
    a = _scalar(seed)
    prefix = _sha512(seed)[32:]
    r = int.from_bytes(_sha512(prefix + message), "little") % L
    big_r = _point_compress(_point_mul(r, _B))
    h = int.from_bytes(
        _sha512(big_r + _point_compress(_point_mul(a, _B)) + message), "little"
    ) % L
    s = (r + h * a) % L
    return big_r + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 verify — False for any malformed input, never raises."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a_point = _point_decompress(public)
    r_point = _point_decompress(signature[:32])
    if a_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(
        _sha512(signature[:32] + public + message), "little"
    ) % L
    s_b = _point_mul(s, _B)
    r_h = _point_add(r_point, _point_mul(h, a_point))
    return _point_equal(s_b, r_h)


def generate_seed() -> bytes:
    """Fresh 32-byte private seed from the OS CSPRNG."""
    return os.urandom(32)
