"""Tests for Shamir secret sharing."""

import random

from quorumvm.config import NUM_CUSTODIANS, PRIME, THRESHOLD
from quorumvm.crypto import shamir


def test_share_reconstruct_basic():
    secret = 42
    shares = shamir.share(secret, NUM_CUSTODIANS, THRESHOLD)
    assert len(shares) == NUM_CUSTODIANS
    recovered = shamir.reconstruct(shares[:THRESHOLD])
    assert recovered == secret


def test_share_reconstruct_all_shares():
    secret = 99999
    shares = shamir.share(secret, NUM_CUSTODIANS, THRESHOLD)
    recovered = shamir.reconstruct(shares)
    assert recovered == secret


def test_reconstruct_any_k_subset():
    """Any K-of-N subset must reconstruct the same secret."""
    secret = 7777
    n, k = 5, 3
    shares = shamir.share(secret, n, k)
    # Try several random subsets of size k
    for _ in range(10):
        subset = random.sample(shares, k)
        assert shamir.reconstruct(subset) == secret


def test_fewer_than_k_fails():
    """Fewer than K shares should NOT reconstruct the correct secret (with
    overwhelming probability)."""
    secret = 123456789
    n, k = 5, 3
    shares = shamir.share(secret, n, k)
    # Take only k-1 shares
    partial = shares[: k - 1]
    # With a 127-bit prime the probability of accidental match is negligible
    recovered = shamir.reconstruct(partial)
    assert recovered != secret


def test_large_secret():
    secret = PRIME - 1
    shares = shamir.share(secret, 3, 2)
    assert shamir.reconstruct(shares[:2]) == secret


def test_zero_secret():
    secret = 0
    shares = shamir.share(secret, 3, 2)
    assert shamir.reconstruct(shares[:2]) == secret


def test_threshold_equals_n():
    """k == n (all shares required)."""
    secret = 555
    n = k = 4
    shares = shamir.share(secret, n, k)
    assert shamir.reconstruct(shares) == secret
    # Any subset of n-1 should fail
    partial = shares[:-1]
    assert shamir.reconstruct(partial) != secret
