"""Tests for the audit log."""

from quorumvm.coordinator.audit import AuditLog


def test_append_and_verify():
    log = AuditLog()
    log.append("install", {"program_id": "abc"})
    log.append("activate", {"program_id": "abc"})
    assert len(log.entries()) == 2
    assert log.verify_chain()


def test_empty_chain():
    log = AuditLog()
    assert log.verify_chain()


def test_chain_links():
    log = AuditLog()
    e1 = log.append("a", {})
    e2 = log.append("b", {})
    assert e2.prev_hash == e1.entry_hash
