"""Tests for prime-field arithmetic."""

from quorumvm.config import PRIME
from quorumvm.crypto import field


def test_add_basic():
    assert field.add(2, 3) == 5


def test_add_wrap():
    assert field.add(PRIME - 1, 2) == 1


def test_sub_basic():
    assert field.sub(10, 3) == 7


def test_sub_underflow():
    result = field.sub(0, 1)
    assert result == PRIME - 1


def test_mul_basic():
    assert field.mul(6, 7) == 42


def test_mul_wrap():
    a = PRIME - 1
    b = 2
    assert field.mul(a, b) == (a * b) % PRIME


def test_inv():
    a = 12345
    a_inv = field.inv(a)
    assert field.mul(a, a_inv) == 1


def test_inv_one():
    assert field.inv(1) == 1


def test_neg():
    a = 42
    assert field.add(a, field.neg(a)) == 0


def test_reduce():
    assert field.reduce(PRIME + 5) == 5
    assert field.reduce(-1) == PRIME - 1
