"""Beaver triple generation for secure multiplication on Shamir shares.

A Beaver triple is a tuple (a, b, c) of random field elements such that
c = a * b  mod p.  When shared via Shamir secret sharing, these triples
enable secure multiplication of two secret-shared values without any
single party learning the operands.

Protocol (for computing z = x * y on shares):
    1. Pre-phase:  generate (a, b, c) with c = a*b, Shamir-share each.
    2. Round 1:    each custodian i computes  ε_i = x_i - a_i
                                              δ_i = y_i - b_i
                   and sends (ε_i, δ_i) to the coordinator.
    3. Reconstruct: coordinator reconstructs ε = x - a  and  δ = y - b
                    (these masked values are safe to reveal).
    4. Round 2:    coordinator sends (ε, δ) to each custodian.
    5. Compute:    each custodian computes
                       z_i = c_i  +  ε * b_i  +  δ * a_i
    6. Final:      coordinator reconstructs z' from the z_i shares,
                   then adds ε * δ  to get  z = x * y.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, List, Tuple

from quorumvm.config import PRIME
from quorumvm.crypto import field
from quorumvm.crypto.shamir import share as shamir_share

Point = Tuple[int, int]


@dataclass
class BeaverTriple:
    """A single Beaver triple (a, b, c) with c = a * b mod p."""

    a: int
    b: int
    c: int

    def verify(self) -> bool:
        """Check that c == a * b mod p."""
        return self.c == field.mul(self.a, self.b)


@dataclass
class BeaverTripleShares:
    """Shamir shares of a Beaver triple for all custodians.

    Attributes
    ----------
    a_shares : list of (x, y) points for secret a
    b_shares : list of (x, y) points for secret b
    c_shares : list of (x, y) points for secret c
    """

    a_shares: List[Point]
    b_shares: List[Point]
    c_shares: List[Point]

    def for_custodian(self, index: int) -> Dict[str, Point]:
        """Return the triple shares for custodian *index* (0-based)."""
        return {
            "a": self.a_shares[index],
            "b": self.b_shares[index],
            "c": self.c_shares[index],
        }


def generate_triple() -> BeaverTriple:
    """Generate a random Beaver triple (a, b, c) with c = a*b mod p."""
    a = secrets.randbelow(PRIME)
    b = secrets.randbelow(PRIME)
    c = field.mul(a, b)
    return BeaverTriple(a=a, b=b, c=c)


def generate_triple_shares(
    n: int,
    k: int,
) -> BeaverTripleShares:
    """Generate a Beaver triple and Shamir-share each component.

    Parameters
    ----------
    n : int
        Number of custodians.
    k : int
        Threshold (minimum shares needed to reconstruct).

    Returns
    -------
    BeaverTripleShares
        Contains n shares for each of a, b, c.
    """
    triple = generate_triple()
    return BeaverTripleShares(
        a_shares=shamir_share(triple.a, n, k),
        b_shares=shamir_share(triple.b, n, k),
        c_shares=shamir_share(triple.c, n, k),
    )


def generate_triples_for_program(
    mul_node_ids: List[str],
    n: int,
    k: int,
) -> Dict[str, BeaverTripleShares]:
    """Generate one Beaver triple per mul node in the program DAG.

    Parameters
    ----------
    mul_node_ids : list of str
        The IDs of all ``mul`` nodes in the IR.
    n, k : int
        Shamir parameters (num custodians, threshold).

    Returns
    -------
    dict mapping node_id → BeaverTripleShares
    """
    return {nid: generate_triple_shares(n, k) for nid in mul_node_ids}


def custodian_mul_round1(
    x_share: int,
    y_share: int,
    a_share_y: int,
    b_share_y: int,
) -> Tuple[int, int]:
    """Custodian's Round-1 computation: compute masked differences.

    Parameters
    ----------
    x_share, y_share : int
        The custodian's Shamir shares of the two mul operands.
    a_share_y, b_share_y : int
        The y-values of the custodian's Beaver triple shares.

    Returns
    -------
    (epsilon_share, delta_share)
        The custodian's shares of ε = x - a and δ = y - b.
    """
    eps = field.sub(x_share, a_share_y)
    delta = field.sub(y_share, b_share_y)
    return eps, delta


def custodian_mul_round2(
    epsilon: int,
    delta: int,
    a_share_y: int,
    b_share_y: int,
    c_share_y: int,
) -> int:
    """Custodian's Round-2 computation: compute result share.

    Given the reconstructed (public) ε and δ, compute the custodian's
    share of the product z = x * y.

    z_i = c_i + ε * b_i + δ * a_i

    (The coordinator will add ε * δ after reconstruction.)
    """
    # z_i = c_i + ε*b_i + δ*a_i
    result = c_share_y
    result = field.add(result, field.mul(epsilon, b_share_y))
    result = field.add(result, field.mul(delta, a_share_y))
    return result


def coordinator_finalize(
    reconstructed_z_prime: int,
    epsilon: int,
    delta: int,
) -> int:
    """Coordinator adds ε*δ to the reconstructed partial product.

    The custodians compute shares of  c + ε*b + δ*a.
    After Lagrange reconstruction that gives  a*b + ε*b + δ*a = c + ε*b + δ*a.
    Adding ε*δ yields:
        c + ε*b + δ*a + ε*δ = (a+ε)(b+δ) = x*y  ✓
    """
    return field.add(reconstructed_z_prime, field.mul(epsilon, delta))
