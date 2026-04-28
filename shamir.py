#!/usr/bin/env python3
"""
Pure-Python Shamir's Secret Sharing over GF(2^8).
No external dependencies beyond the standard library.

GF(2^8) uses the AES irreducible polynomial x^8+x^4+x^3+x+1 (0x11B)
with generator g=3 (primitive element of order 255).
"""

import secrets
from typing import List, Tuple


def _gf_mul_direct(a: int, b: int) -> int:
    """Carry-less multiplication mod 0x11B (for table build only)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result


# Build exp/log tables with generator 3 (primitive root of GF(2^8)/0x11B)
_GF_EXP: List[int] = [0] * 512
_GF_LOG: List[int] = [0] * 256

_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x = _gf_mul_direct(_x, 3)
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(x: int) -> int:
    if x == 0:
        raise ZeroDivisionError("no inverse of 0 in GF(2^8)")
    return _GF_EXP[255 - _GF_LOG[x]]


def _poly_eval(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial via Horner's method in GF(2^8)."""
    result = 0
    for coeff in reversed(coeffs):
        result = _gf_mul(result, x) ^ coeff
    return result


def _lagrange_at_zero(points: List[Tuple[int, int]]) -> int:
    """
    Recover f(0) via Lagrange interpolation over GF(2^8).
    In GF(2^8): subtraction == XOR, so (0 - xj) = xj and (xi - xj) = xi ^ xj.
    """
    x_vals = [p[0] for p in points]
    y_vals = [p[1] for p in points]
    result = 0
    for i in range(len(points)):
        xi, yi = x_vals[i], y_vals[i]
        num = 1
        den = 1
        for j in range(len(points)):
            if i == j:
                continue
            xj = x_vals[j]
            num = _gf_mul(num, xj)
            den = _gf_mul(den, xi ^ xj)
        result ^= _gf_mul(yi, _gf_mul(num, _gf_inv(den)))
    return result


def split_secret(secret: bytes, n: int, m: int) -> List[bytes]:
    """
    Split `secret` into `n` shares with threshold `m`.
    Each returned share: first byte = x-coord (1..n), rest = share data.
    Requirements: 1 <= m <= n <= 255.
    """
    if not (1 <= m <= n <= 255):
        raise ValueError(f"Need 1 <= m <= n <= 255, got m={m}, n={n}")
    if not secret:
        raise ValueError("Secret must be non-empty")

    shares_data: List[List[int]] = [[] for _ in range(n)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(m - 1)]
        for idx in range(n):
            shares_data[idx].append(_poly_eval(coeffs, idx + 1))

    return [bytes([i + 1]) + bytes(data) for i, data in enumerate(shares_data)]


def recover_secret(shares: List[bytes]) -> bytes:
    """
    Recover the original secret from share blobs returned by split_secret.
    Provide at least m shares; extra shares are handled correctly.
    """
    if not shares:
        raise ValueError("No shares provided")
    secret_len = len(shares[0]) - 1
    if secret_len < 1:
        raise ValueError("Share too short")
    unpacked: List[Tuple[int, bytes]] = []
    for sh in shares:
        if len(sh) - 1 != secret_len:
            raise ValueError("Share length mismatch")
        unpacked.append((sh[0], sh[1:]))

    result = bytearray(secret_len)
    for byte_idx in range(secret_len):
        points = [(x, y[byte_idx]) for x, y in unpacked]
        result[byte_idx] = _lagrange_at_zero(points)
    return bytes(result)
