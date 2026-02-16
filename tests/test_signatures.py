"""Tests for HMAC signatures."""

from quorumvm.crypto import signatures


def test_sign_verify():
    msg = "test-program-id-abc123"
    sig = signatures.sign(0, msg)
    assert signatures.verify(0, msg, sig)


def test_wrong_key():
    msg = "test-program-id-abc123"
    sig = signatures.sign(0, msg)
    assert not signatures.verify(1, msg, sig)


def test_tampered_message():
    msg = "test-program-id-abc123"
    sig = signatures.sign(0, msg)
    assert not signatures.verify(0, msg + "x", sig)
