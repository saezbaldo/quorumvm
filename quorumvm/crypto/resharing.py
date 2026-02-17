"""Proactive resharing and custodian rotation for Shamir shares.

Proactive resharing refreshes all shares of a secret **without
reconstructing it**, so that an adversary who learns old shares
gains no advantage.

Protocol (among the current K-of-N holders):

1. Each participating custodian *i* generates a random polynomial
   ``g_i`` of degree ``k-1`` with ``g_i(0) = 0`` (a "share of zero").
2. Custodian *i* evaluates ``g_i(x_j)`` for every target custodian *j*
   and sends the **sub-share** ``δ_{i→j} = g_i(x_j)`` to custodian *j*.
3. Custodian *j* adds all received sub-shares to its current share:
   ``y'_j = y_j + Σ_i δ_{i→j}  (mod p)``

Because ``Σ g_i(0) = 0``, the new shares still interpolate to the same
secret, but the underlying polynomial is different, invalidating any
previously leaked shares.

Custodian rotation (onboard / retire) works by combining resharing with
Lagrange interpolation to transfer shares to a new set of custodians
without ever reconstructing the secret.
"""

from __future__ import annotations

import secrets
from typing import Dict, List, Tuple

from quorumvm.config import PRIME
from quorumvm.crypto import field

Point = Tuple[int, int]


# -----------------------------------------------------------------------
# Zero-share polynomial generation
# -----------------------------------------------------------------------

def _random_field_element() -> int:
    return secrets.randbelow(PRIME)


def generate_zero_share_poly(k: int) -> List[int]:
    """Generate a random polynomial of degree ``k-1`` with constant term 0.

    Returns coefficients ``[0, a_1, ..., a_{k-1}]``.
    """
    return [0] + [_random_field_element() for _ in range(k - 1)]


def eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at *x* using Horner's method in F_p."""
    result = 0
    for c in reversed(coeffs):
        result = field.add(field.mul(result, x), c)
    return result


# -----------------------------------------------------------------------
# Sub-share generation (one custodian → all targets)
# -----------------------------------------------------------------------

def generate_sub_shares(
    k: int,
    target_x_coords: List[int],
) -> Dict[int, int]:
    """Generate sub-shares for a resharing round.

    A random degree-(k-1) polynomial g with g(0)=0 is created.
    Returns ``{x_j: g(x_j)}`` for each target x-coordinate.
    """
    g = generate_zero_share_poly(k)
    return {x: eval_poly(g, x) for x in target_x_coords}


def generate_sub_shares_from_poly(
    poly: List[int],
    target_x_coords: List[int],
) -> Dict[int, int]:
    """Evaluate an already-created zero-share polynomial at target points."""
    return {x: eval_poly(poly, x) for x in target_x_coords}


# -----------------------------------------------------------------------
# Apply sub-shares (receiving custodian accumulates)
# -----------------------------------------------------------------------

def apply_sub_shares(
    current_share_y: int,
    received_sub_shares: List[int],
) -> int:
    """Add all received sub-shares to the current share y-value.

    ``y' = y + Σ δ_{i→j}  (mod p)``
    """
    result = current_share_y
    for delta in received_sub_shares:
        result = field.add(result, delta)
    return result


# -----------------------------------------------------------------------
# Full resharing round (all-at-once helper for tests / demos)
# -----------------------------------------------------------------------

def reshare(
    shares: List[Point],
    k: int,
    target_x_coords: List[int] | None = None,
) -> List[Point]:
    """Perform a full proactive resharing round.

    Each share-holder generates a zero-share polynomial and sends
    sub-shares to all targets.  By default the targets are the same
    x-coordinates as the current holders (periodic resharing).

    Parameters
    ----------
    shares : list of (x, y)
        At least *k* current shares.
    k : int
        Threshold.
    target_x_coords : list of int or None
        X-coordinates for the new shares.  Defaults to the current
        holders' x-coordinates.

    Returns
    -------
    list of (x, y')
        New shares that still reconstruct to the same secret.
    """
    if len(shares) < k:
        raise ValueError(f"Need >= k={k} shares for resharing, got {len(shares)}")

    if target_x_coords is None:
        target_x_coords = [x for x, _ in shares]

    # Each holder generates a zero-share poly and sub-shares
    # sub_shares_per_target[x_j] = list of δ values from each holder
    sub_shares_per_target: Dict[int, List[int]] = {x: [] for x in target_x_coords}

    for _x_i, _y_i in shares:
        g = generate_zero_share_poly(k)
        for x_j in target_x_coords:
            delta = eval_poly(g, x_j)
            sub_shares_per_target[x_j].append(delta)

    # Build new shares — if a target has a current share, add sub-shares.
    # If it's a new target (rotation), its share starts from the
    # Lagrange-interpolated value at that x-coordinate.
    current_map: Dict[int, int] = {x: y for x, y in shares}

    new_shares: List[Point] = []
    for x_j in target_x_coords:
        if x_j in current_map:
            base_y = current_map[x_j]
        else:
            # New custodian: interpolate the current polynomial at x_j
            # using k points, then add sub-shares
            base_y = _lagrange_at(shares[:k], x_j)
        new_y = apply_sub_shares(base_y, sub_shares_per_target[x_j])
        new_shares.append((x_j, new_y))

    return new_shares


# -----------------------------------------------------------------------
# Rotation helpers
# -----------------------------------------------------------------------

def rotate_custodians(
    shares: List[Point],
    k: int,
    new_n: int,
    new_x_coords: List[int] | None = None,
) -> List[Point]:
    """Transfer shares to a new set of custodians without reconstructing.

    Combines Lagrange interpolation with resharing to move shares to
    a new set of ``new_n`` custodians.

    Parameters
    ----------
    shares : list of (x, y)
        At least *k* current shares.
    k : int
        Threshold (must be <= new_n).
    new_n : int
        Number of new custodians.
    new_x_coords : list of int or None
        X-coordinates for the new custodians.  Defaults to 1..new_n.

    Returns
    -------
    list of (x, y)
        New shares for the new custodians.
    """
    if len(shares) < k:
        raise ValueError(f"Need >= k={k} shares for rotation, got {len(shares)}")
    if k > new_n:
        raise ValueError(f"Threshold k={k} > new_n={new_n}")

    if new_x_coords is None:
        new_x_coords = list(range(1, new_n + 1))

    return reshare(shares, k, target_x_coords=new_x_coords)


# -----------------------------------------------------------------------
# Lagrange interpolation at arbitrary x (not just x=0)
# -----------------------------------------------------------------------

def _lagrange_at(points: List[Point], x_target: int) -> int:
    """Evaluate the Lagrange polynomial at ``x_target`` given ``points``."""
    k = len(points)
    result = 0
    for j in range(k):
        xj, yj = points[j]
        num = 1
        den = 1
        for m in range(k):
            if m == j:
                continue
            xm = points[m][0]
            num = field.mul(num, field.sub(x_target, xm))
            den = field.mul(den, field.sub(xj, xm))
        lagrange_coeff = field.mul(num, field.inv(den))
        result = field.add(result, field.mul(yj, lagrange_coeff))
    return result
