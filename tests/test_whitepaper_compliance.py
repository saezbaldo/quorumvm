"""Whitepaper-compliance test suite.

Maps every security invariant from PLAN-B Whitepaper §4, §6, §8, §11
to an automated, reproducible test.

Tests use FastAPI TestClient (in-process, no Docker) and mock
inter-service HTTP calls where needed so the full coordinator → custodian
flow runs in a single process.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from quorumvm.compiler.dsl_parser import compile_source
from quorumvm.compiler.package import PolicyManifest, build_package
from quorumvm.config import NUM_CUSTODIANS, PRIME, THRESHOLD
from quorumvm.coordinator import app as coord_module
from quorumvm.coordinator.policy import PolicyEngine
from quorumvm.crypto import shamir, signatures
from quorumvm.custodian.app import CustodianState, create_app as create_custodian_app
from quorumvm.custodian.executor import evaluate_ir


# =========================================================================
# Shared helpers
# =========================================================================

SAMPLE_SRC = """\
input x
const c = 7
add t = x c
mul y = t t
output y
"""


def _fresh_env():
    """Return a clean coordinator TestClient + list of custodian TestClients."""
    coord_module._packages.clear()
    coord_module._approvals.clear()
    coord_module._status.clear()
    coord_module._policy = PolicyEngine()
    coord_module._audit = coord_module.AuditLog()

    coordinator = TestClient(coord_module.app)

    custodian_clients = []
    custodian_states = []
    for i in range(NUM_CUSTODIANS):
        state = CustodianState(i)
        custodian_states.append(state)
        custodian_clients.append(TestClient(create_custodian_app(state)))

    return coordinator, custodian_clients, custodian_states


def _compile_and_package(policy: PolicyManifest | None = None):
    ir = compile_source(SAMPLE_SRC)
    if policy is None:
        policy = PolicyManifest(
            cost_per_eval=1, budget_per_identity=5, max_evals_per_minute=1000
        )
    pkg = build_package(ir, policy=policy)
    return ir, pkg


def _install_on_custodians(custodian_clients, pkg, shares):
    pkg_dict = pkg.model_dump()
    for i, cc in enumerate(custodian_clients):
        x, y = shares[i]
        resp = cc.post(
            "/install",
            json={"program_package": pkg_dict, "share_x": str(x), "share_y": str(y)},
        )
        assert resp.status_code == 200


def _install_on_coordinator(coordinator, pkg):
    resp = coordinator.post(
        "/install", json={"program_package": pkg.model_dump()}
    )
    assert resp.status_code == 200


def _approve_k(coordinator, custodian_clients, program_id, k=THRESHOLD):
    """Collect exactly *k* approvals and forward to coordinator."""
    for i in range(k):
        resp = custodian_clients[i].post(
            "/approve", json={"program_id": program_id}
        )
        assert resp.status_code == 200
        approval = resp.json()
        resp = coordinator.post(
            "/approve",
            json={
                "program_id": program_id,
                "custodian_index": approval["custodian_index"],
                "signature": approval["signature"],
            },
        )
        assert resp.status_code == 200
    return resp.json()


def _mock_custodian_eval(custodian_clients, pkg):
    """Return an async side-effect for httpx that routes to in-process custodians."""

    async def _fake_post(url: str, *, json: dict, **kw):
        """Route coordinator's outbound HTTP to in-process custodian TestClients."""
        for i, cc in enumerate(custodian_clients):
            if f"custodian-{i}" in url and "/eval_share" in url:
                resp = cc.post("/eval_share", json=json)

                class _FakeResp:
                    status_code = resp.status_code

                    def raise_for_status(self):
                        if self.status_code >= 400:
                            raise Exception(f"HTTP {self.status_code}")

                    def json(self_inner):
                        return resp.json()

                return _FakeResp()
        raise Exception(f"No custodian matched URL {url}")

    return _fake_post


# =========================================================================
# §4.1 — No single point of authority
# Fewer than K approvals must NOT activate the program.
# =========================================================================


class TestThresholdApprovals:
    """Whitepaper §4.1 + §9: version activation requires K-of-N."""

    def test_fewer_than_k_approvals_stays_pending(self):
        """< K approvals → program remains PENDING."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)

        # Send only K-1 approvals
        for i in range(THRESHOLD - 1):
            resp = custodian_clients[i].post(
                "/approve", json={"program_id": pkg.program_id}
            )
            approval = resp.json()
            coordinator.post(
                "/approve",
                json={
                    "program_id": pkg.program_id,
                    "custodian_index": approval["custodian_index"],
                    "signature": approval["signature"],
                },
            )

        resp = coordinator.get(f"/status/{pkg.program_id}")
        assert resp.json()["status"] == "PENDING", \
            "Program must remain PENDING with fewer than K approvals"

    def test_exactly_k_approvals_activates(self):
        """Exactly K approvals → program becomes ACTIVE."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        result = _approve_k(coordinator, custodian_clients, pkg.program_id)

        assert result["status"] == "ACTIVE"
        assert result["approvals"] >= THRESHOLD

    def test_invalid_signature_rejected(self):
        """A forged approval signature is rejected (403)."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)

        resp = coordinator.post(
            "/approve",
            json={
                "program_id": pkg.program_id,
                "custodian_index": 0,
                "signature": "forged-signature-value",
            },
        )
        assert resp.status_code == 403


# =========================================================================
# §4.1 continued — eval rejected when program is PENDING
# =========================================================================


class TestEvalRequiresActive:
    """Whitepaper §4.1: execution requires active (quorum-approved) version."""

    def test_eval_rejected_when_pending(self):
        """POST /eval on a PENDING program returns 400."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        # Do NOT approve — stays PENDING

        resp = coordinator.post(
            "/eval",
            json={
                "identity_id": "alice",
                "program_id": pkg.program_id,
                "inputs": {"x": 3},
            },
        )
        assert resp.status_code == 400, \
            "Eval must be rejected when program is not ACTIVE"

    def test_eval_nonexistent_program_returns_404(self):
        """POST /eval on unknown program_id → 404."""
        coordinator, _, _ = _fresh_env()
        resp = coordinator.post(
            "/eval",
            json={
                "identity_id": "alice",
                "program_id": "nonexistent-id",
                "inputs": {"x": 1},
            },
        )
        assert resp.status_code == 404


# =========================================================================
# §4.2 — No single point of knowledge
# Fewer than K shares cannot reconstruct S_v.
# =========================================================================


class TestThresholdSecretSharing:
    """Whitepaper §4.2 + §6: secret sharing protects S_v."""

    def test_k_shares_reconstruct_correctly(self):
        """K shares of S_v reconstruct to the correct secret."""
        S_v = 123456789
        shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
        result = shamir.reconstruct(shares[:THRESHOLD])
        assert result == S_v

    def test_fewer_than_k_shares_do_not_reconstruct(self):
        """K-1 shares fail to reconstruct S_v."""
        S_v = 123456789
        shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
        if THRESHOLD > 1:
            wrong = shamir.reconstruct(shares[: THRESHOLD - 1])
            assert wrong != S_v, \
                "K-1 shares must NOT reconstruct the secret"

    def test_fewer_than_k_output_shares_wrong_result_e2e(self):
        """End-to-end: evaluating with < K custodian outputs and
        attempting Lagrange reconstruction gives wrong answer."""
        _, custodian_clients, _ = _fresh_env()
        ir, pkg = _compile_and_package()
        S_v = 42
        shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
        _install_on_custodians(custodian_clients, pkg, shares)

        x_val = 5
        input_shares = shamir.share(x_val, NUM_CUSTODIANS, THRESHOLD)

        partial = []
        for i in range(THRESHOLD - 1):
            ix, iy = input_shares[i]
            resp = custodian_clients[i].post(
                "/eval_share",
                json={
                    "program_id": pkg.program_id,
                    "request_id": "wp-partial",
                    "input_shares": {"x": {"x": ix, "y": str(iy)}},
                },
            )
            body = resp.json()
            partial.append((body["x"], int(str(body["y"]))))

        if partial:
            wrong = shamir.reconstruct(partial)
            expected = ((x_val + 7) ** 2) % PRIME
            assert wrong != expected


# =========================================================================
# §4.3 / §8 — Oracle access is governed
# =========================================================================


class TestBudgetEnforcement:
    """Whitepaper §8: identity-bound budget enforcement."""

    def test_budget_allows_then_denies(self):
        """Budget of 2 allows 2 evals, then denies the 3rd."""
        engine = PolicyEngine()
        engine.register("p1", {
            "cost_per_eval": 1,
            "budget_per_identity": 2,
            "max_evals_per_minute": 1000,
        })
        assert engine.check("p1", "alice") is None
        assert engine.check("p1", "alice") is None
        denial = engine.check("p1", "alice")
        assert denial is not None
        assert "budget" in denial

    def test_budget_per_identity_isolation(self):
        """Budgets are tracked per identity; alice exhausted ≠ bob blocked."""
        engine = PolicyEngine()
        engine.register("p1", {
            "cost_per_eval": 1,
            "budget_per_identity": 1,
            "max_evals_per_minute": 1000,
        })
        assert engine.check("p1", "alice") is None
        assert engine.check("p1", "alice") is not None  # denied
        assert engine.check("p1", "bob") is None         # bob still ok

    def test_budget_via_coordinator_endpoint(self):
        """Full HTTP flow: budget exhaustion through /eval endpoint."""
        coordinator, custodian_clients, _ = _fresh_env()
        policy = PolicyManifest(
            cost_per_eval=1, budget_per_identity=2, max_evals_per_minute=1000
        )
        _, pkg = _compile_and_package(policy)
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        _approve_k(coordinator, custodian_clients, pkg.program_id)

        fake_post = _mock_custodian_eval(custodian_clients, pkg)

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = fake_post
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            # First 2 should succeed
            for _ in range(2):
                resp = coordinator.post(
                    "/eval",
                    json={
                        "identity_id": "alice",
                        "program_id": pkg.program_id,
                        "inputs": {"x": 3},
                    },
                )
                assert resp.status_code == 200

            # Third should be denied (budget exhausted)
            resp = coordinator.post(
                "/eval",
                json={
                    "identity_id": "alice",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 3},
                },
            )
            assert resp.status_code == 429
            assert "budget" in resp.json()["detail"]


class TestRateLimitEnforcement:
    """Whitepaper §8: token-bucket rate limiting."""

    def test_rate_limit_unit(self):
        """PolicyEngine denies requests after burst exceeds capacity."""
        engine = PolicyEngine()
        engine.register("p1", {
            "cost_per_eval": 1,
            "budget_per_identity": 1000,
            "max_evals_per_minute": 2,  # tiny burst
        })
        assert engine.check("p1", "alice") is None
        assert engine.check("p1", "alice") is None
        denial = engine.check("p1", "alice")
        assert denial is not None
        assert "rate limit" in denial

    def test_rate_limit_refills_over_time(self):
        """After a brief wait, tokens refill and requests are allowed again."""
        engine = PolicyEngine()
        engine.register("p1", {
            "cost_per_eval": 1,
            "budget_per_identity": 1000,
            "max_evals_per_minute": 60,  # 1 token/sec refill
        })
        # Drain all tokens
        for _ in range(60):
            engine.check("p1", "alice")

        # Should be denied now
        assert engine.check("p1", "alice") is not None

        # Wait just over 1 second for refill
        time.sleep(1.1)
        assert engine.check("p1", "alice") is None, \
            "Token bucket should refill over time"

    def test_rate_limit_via_coordinator_endpoint(self):
        """Full HTTP flow: rate limit through /eval endpoint."""
        coordinator, custodian_clients, _ = _fresh_env()
        policy = PolicyManifest(
            cost_per_eval=1, budget_per_identity=1000, max_evals_per_minute=2
        )
        _, pkg = _compile_and_package(policy)
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        _approve_k(coordinator, custodian_clients, pkg.program_id)

        fake_post = _mock_custodian_eval(custodian_clients, pkg)

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = fake_post
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            # First 2 within burst
            for _ in range(2):
                resp = coordinator.post(
                    "/eval",
                    json={
                        "identity_id": "ratelimit-user",
                        "program_id": pkg.program_id,
                        "inputs": {"x": 3},
                    },
                )
                assert resp.status_code == 200

            # Third should be rate limited
            resp = coordinator.post(
                "/eval",
                json={
                    "identity_id": "ratelimit-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 3},
                },
            )
            assert resp.status_code == 429
            assert "rate limit" in resp.json()["detail"]


class TestAuditChainIntegrity:
    """Whitepaper §8: immutable audit log with hash-chain."""

    def test_audit_chain_valid_after_full_flow(self):
        """After install + activate, audit chain is valid."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        _approve_k(coordinator, custodian_clients, pkg.program_id)

        resp = coordinator.get("/audit")
        audit = resp.json()
        assert audit["chain_valid"] is True
        # install + K approvals + activate
        assert len(audit["entries"]) >= THRESHOLD + 2

    def test_audit_records_eval_events(self):
        """Successful evals and denials appear in the audit log."""
        coordinator, custodian_clients, _ = _fresh_env()
        policy = PolicyManifest(
            cost_per_eval=1, budget_per_identity=1, max_evals_per_minute=1000
        )
        _, pkg = _compile_and_package(policy)
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        _approve_k(coordinator, custodian_clients, pkg.program_id)

        fake_post = _mock_custodian_eval(custodian_clients, pkg)

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = fake_post
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            # 1 success
            coordinator.post(
                "/eval",
                json={
                    "identity_id": "audit-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 3},
                },
            )
            # 1 denial (budget=1 exhausted)
            coordinator.post(
                "/eval",
                json={
                    "identity_id": "audit-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 3},
                },
            )

        resp = coordinator.get("/audit")
        audit = resp.json()
        events = [e["event"] for e in audit["entries"]]
        assert "eval_ok" in events
        assert "eval_denied" in events
        assert audit["chain_valid"] is True

    def test_audit_entries_are_hash_chained(self):
        """Each entry's prev_hash matches the prior entry's entry_hash."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        _approve_k(coordinator, custodian_clients, pkg.program_id)

        resp = coordinator.get("/audit")
        entries = resp.json()["entries"]
        assert len(entries) >= 2

        for i in range(1, len(entries)):
            assert entries[i]["prev_hash"] == entries[i - 1]["entry_hash"], \
                f"Chain broken at entry {i}"


# =========================================================================
# §4.5 — Graceful degradation
# =========================================================================


class TestGracefulDegradation:
    """Whitepaper §4.5: security degrades gracefully."""

    def test_one_custodian_down_quorum_still_works(self):
        """With 1 of N custodians unreachable, eval still succeeds
        because the coordinator only needs K responses."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        _approve_k(coordinator, custodian_clients, pkg.program_id)

        # Build a mock that makes custodian-2 unreachable
        async def _partial_post(url: str, *, json: dict, **kw):
            for i, cc in enumerate(custodian_clients):
                if f"custodian-{i}" in url and "/eval_share" in url:
                    if i == NUM_CUSTODIANS - 1:
                        # Simulate custodian down
                        raise ConnectionError("custodian unreachable")
                    resp = cc.post("/eval_share", json=json)

                    class _R:
                        status_code = resp.status_code
                        def raise_for_status(self):
                            if self.status_code >= 400:
                                raise Exception(f"HTTP {self.status_code}")
                        def json(self_inner):
                            return resp.json()

                    return _R()
            raise Exception(f"Unmatched URL {url}")

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = _partial_post
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            resp = coordinator.post(
                "/eval",
                json={
                    "identity_id": "degradation-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 3},
                },
            )
            # K=2, N=3, 1 down → 2 respond → should still succeed
            assert resp.status_code == 200
            expected = ((3 + 7) ** 2) % PRIME
            assert resp.json()["result"] == expected

    def test_too_many_custodians_down_fails(self):
        """If more than N-K custodians are down, eval fails with 503."""
        coordinator, custodian_clients, _ = _fresh_env()
        _, pkg = _compile_and_package()
        shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

        _install_on_custodians(custodian_clients, pkg, shares)
        _install_on_coordinator(coordinator, pkg)
        _approve_k(coordinator, custodian_clients, pkg.program_id)

        # Make all but K-1 custodians unreachable (i.e. N-K+1 are down)
        alive = THRESHOLD - 1  # not enough

        async def _mostly_dead_post(url: str, *, json: dict, **kw):
            for i, cc in enumerate(custodian_clients):
                if f"custodian-{i}" in url and "/eval_share" in url:
                    if i >= alive:
                        raise ConnectionError("custodian unreachable")
                    resp = cc.post("/eval_share", json=json)

                    class _R:
                        status_code = resp.status_code
                        def raise_for_status(self):
                            if self.status_code >= 400:
                                raise Exception(f"HTTP {self.status_code}")
                        def json(self_inner):
                            return resp.json()

                    return _R()
            raise Exception(f"Unmatched URL {url}")

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = _mostly_dead_post
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            resp = coordinator.post(
                "/eval",
                json={
                    "identity_id": "dead-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 3},
                },
            )
            assert resp.status_code == 503


# =========================================================================
# §11 — Full developer workflow E2E
# =========================================================================


class TestFullWhitepaperFlow:
    """Whitepaper §11 criterion 4: compile → activate → evaluate → observe.

    This is the "golden path" test that exercises the entire whitepaper
    workflow in a single scenario.
    """

    def test_complete_e2e_flow(self):
        """compile → install → activate → eval → budget deny → audit verify."""
        coordinator, custodian_clients, _ = _fresh_env()

        # ---- Step 1: Compile ----
        ir = compile_source(SAMPLE_SRC)
        assert len(ir.nodes) == 4
        assert ir.output_node_id == "y"

        # ---- Step 2: Build package ----
        policy = PolicyManifest(
            cost_per_eval=1, budget_per_identity=3, max_evals_per_minute=1000
        )
        pkg = build_package(ir, policy=policy)
        assert len(pkg.program_id) == 64  # SHA-256 hex

        # ---- Step 3: Generate secret and shares ----
        S_v = 999999
        shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
        assert len(shares) == NUM_CUSTODIANS
        reconstructed = shamir.reconstruct(shares[:THRESHOLD])
        assert reconstructed == S_v

        # ---- Step 4: Install on custodians ----
        _install_on_custodians(custodian_clients, pkg, shares)

        # ---- Step 5: Install on coordinator ----
        _install_on_coordinator(coordinator, pkg)

        # Verify PENDING
        resp = coordinator.get(f"/status/{pkg.program_id}")
        assert resp.json()["status"] == "PENDING"

        # ---- Step 6: Activate (K approvals) ----
        result = _approve_k(coordinator, custodian_clients, pkg.program_id)
        assert result["status"] == "ACTIVE"

        # ---- Step 7: Evaluate — verify correct outputs ----
        fake_post = _mock_custodian_eval(custodian_clients, pkg)

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = fake_post
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            test_cases = [
                (3, ((3 + 7) ** 2) % PRIME),    # 100
                (10, ((10 + 7) ** 2) % PRIME),   # 289
                (0, ((0 + 7) ** 2) % PRIME),     # 49
            ]
            for x_val, expected in test_cases:
                resp = coordinator.post(
                    "/eval",
                    json={
                        "identity_id": "e2e-user",
                        "program_id": pkg.program_id,
                        "inputs": {"x": x_val},
                    },
                )
                assert resp.status_code == 200
                assert resp.json()["result"] == expected, \
                    f"f({x_val}) expected {expected}, got {resp.json()['result']}"

            # ---- Step 8: Budget exhaustion (budget=3, used 3) ----
            resp = coordinator.post(
                "/eval",
                json={
                    "identity_id": "e2e-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 1},
                },
            )
            assert resp.status_code == 429
            assert "budget" in resp.json()["detail"]

        # ---- Step 9: Audit log integrity ----
        resp = coordinator.get("/audit")
        audit = resp.json()
        assert audit["chain_valid"] is True
        events = [e["event"] for e in audit["entries"]]
        assert "install" in events
        assert "approve" in events
        assert "activate" in events
        assert "eval_ok" in events
        assert "eval_denied" in events

        # Verify hash chain manually
        entries = audit["entries"]
        for i in range(1, len(entries)):
            assert entries[i]["prev_hash"] == entries[i - 1]["entry_hash"]
