"""Shamir (K-of-N) secret sharing over F_p.

API
---
share(secret, n, k)  -> list of (x_i, y_i)  with x_i = 1..n
reconstruct(points)  -> secret   (needs >= k points)
"""

from __future__ import annotations

import secrets
from typing import List, Tuple

from quorumvm.config import PRIME
from quorumvm.crypto import field

Point = Tuple[int, int]


def _random_field_element() -> int:
    """Return a uniform random element in [0, PRIME)."""
    return secrets.randbelow(PRIME)


def share(secret: int, n: int, k: int) -> List[Point]:
    """Split *secret* into *n* shares with threshold *k*.

    A random polynomial f of degree k-1 is chosen such that f(0) = secret.
    Shares are (i, f(i)) for i = 1 … n.
    """
    if k < 1 or k > n:
        raise ValueError(f"Invalid threshold: k={k}, n={n}")
    secret = field.reduce(secret)

    # Random coefficients a_1 … a_{k-1}
    coeffs = [secret] + [_random_field_element() for _ in range(k - 1)]

    shares: List[Point] = []
    for i in range(1, n + 1):
        y = _eval_poly(coeffs, i)
        shares.append((i, y))
    return shares


def reconstruct(points: List[Point]) -> int:
    """Reconstruct secret from *points* using Lagrange interpolation at x=0."""
    if not points:
        raise ValueError("Need at least one point")
    k = len(points)
    secret = 0
    for j in range(k):
        xj, yj = points[j]
        num = 1
        den = 1
        for m in range(k):
            if m == j:
                continue
            xm = points[m][0]
            num = field.mul(num, field.neg(xm))          # (0 - x_m)
            den = field.mul(den, field.sub(xj, xm))      # (x_j - x_m)
        lagrange = field.mul(num, field.inv(den))
        secret = field.add(secret, field.mul(yj, lagrange))
    return secret


def _eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial (Horner's method) mod PRIME."""
    result = 0
    for c in reversed(coeffs):
        result = field.add(field.mul(result, x), c)
    return result
