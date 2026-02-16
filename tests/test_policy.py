"""Tests for the policy engine."""

from quorumvm.coordinator.policy import PolicyEngine


def _make_policy(**overrides):
    defaults = {
        "cost_per_eval": 1,
        "budget_per_identity": 3,
        "max_evals_per_minute": 60,
    }
    defaults.update(overrides)
    return defaults


def test_budget_exhaustion():
    engine = PolicyEngine()
    engine.register("p1", _make_policy(budget_per_identity=2))

    assert engine.check("p1", "alice") is None  # 1st ok
    assert engine.check("p1", "alice") is None  # 2nd ok
    reason = engine.check("p1", "alice")
    assert reason is not None and "budget" in reason


def test_separate_identities():
    engine = PolicyEngine()
    engine.register("p1", _make_policy(budget_per_identity=1))

    assert engine.check("p1", "alice") is None
    assert engine.check("p1", "alice") is not None  # alice exhausted
    assert engine.check("p1", "bob") is None  # bob still has budget


def test_unregistered_program():
    engine = PolicyEngine()
    reason = engine.check("unknown", "alice")
    assert reason is not None and "not registered" in reason
