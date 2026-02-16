"""Prime-field arithmetic F_p.

All values are Python ints reduced mod PRIME.
"""

from __future__ import annotations

from quorumvm.config import PRIME


def add(a: int, b: int) -> int:
    """Field addition."""
    return (a + b) % PRIME


def sub(a: int, b: int) -> int:
    """Field subtraction."""
    return (a - b) % PRIME


def mul(a: int, b: int) -> int:
    """Field multiplication."""
    return (a * b) % PRIME


def inv(a: int) -> int:
    """Multiplicative inverse via Fermat's little theorem (p is prime)."""
    if a % PRIME == 0:
        raise ZeroDivisionError("Cannot invert zero in F_p")
    return pow(a, PRIME - 2, PRIME)


def neg(a: int) -> int:
    """Additive inverse."""
    return (-a) % PRIME


def reduce(a: int) -> int:
    """Reduce an integer into [0, PRIME)."""
    return a % PRIME
