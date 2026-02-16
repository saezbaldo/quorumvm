"""End-to-end integration tests using in-process ASGI TestClients.

These tests spin up the coordinator and custodian apps in the same
process (no Docker needed) and exercise the full install → activate →
evaluate workflow.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Set custodian env vars BEFORE importing apps
os.environ.setdefault("CUSTODIAN_INDEX", "0")

from quorumvm.compiler.dsl_parser import compile_source
from quorumvm.compiler.package import PolicyManifest, build_package
from quorumvm.config import NUM_CUSTODIANS, PRIME, THRESHOLD
from quorumvm.coordinator import app as coord_module
from quorumvm.crypto import shamir, signatures
from quorumvm.custodian.app import CustodianState, create_app as create_custodian_app


# ---------- helpers --------------------------------------------------------

SAMPLE_SRC = """\
input x
const c = 7
add t = x c
mul y = t t
output y
"""


@pytest.fixture()
def setup():
    """Set up fresh coordinator + custodian test clients."""
    # Fresh coordinator state
    coord_module._packages.clear()
    coord_module._approvals.clear()
    coord_module._status.clear()
    coord_module._policy = coord_module.PolicyEngine()
    coord_module._audit = coord_module.AuditLog()

    coordinator = TestClient(coord_module.app)

    # Create custodian apps – each with its own isolated state
    custodian_clients = []
    for i in range(NUM_CUSTODIANS):
        state = CustodianState(i)
        capp = create_custodian_app(state)
        custodian_clients.append(TestClient(capp))

    return coordinator, custodian_clients


def _install_and_activate(coordinator, custodian_clients, pkg, shares):
    """Helper: install on all custodians + coordinator, then activate."""
    pkg_dict = pkg.model_dump()

    # Install on custodians
    for i, cc in enumerate(custodian_clients):
        x, y = shares[i]
        resp = cc.post(
            "/install",
            json={"program_package": pkg_dict, "share_x": str(x), "share_y": str(y)},
        )
        assert resp.status_code == 200

    # Install on coordinator
    resp = coordinator.post("/install", json={"program_package": pkg_dict})
    assert resp.status_code == 200

    # Approve (K custodians)
    for i in range(THRESHOLD):
        resp = custodian_clients[i].post(
            "/approve", json={"program_id": pkg.program_id}
        )
        assert resp.status_code == 200
        approval = resp.json()

        resp = coordinator.post(
            "/approve",
            json={
                "program_id": pkg.program_id,
                "custodian_index": approval["custodian_index"],
                "signature": approval["signature"],
            },
        )
        assert resp.status_code == 200

    # Verify active
    resp = coordinator.get(f"/status/{pkg.program_id}")
    assert resp.json()["status"] == "ACTIVE"


# ---------- tests ----------------------------------------------------------


def test_install_and_activate(setup):
    coordinator, custodian_clients = setup

    ir = compile_source(SAMPLE_SRC)
    pkg = build_package(ir)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    _install_and_activate(coordinator, custodian_clients, pkg, shares)


def test_eval_deterministic(setup):
    """Evaluate a program and verify the output matches plain computation.

    MVP model: the coordinator sends the full input values to each
    custodian (not Shamir-split inputs), each custodian evaluates the
    DAG independently and produces the same result.  The coordinator
    could then verify consistency.  Threshold secret sharing protects
    the *program secret* S_v, not the inputs themselves.

    For demonstration we send the plain input value as the share to
    every custodian and verify all produce the correct answer.
    """
    coordinator, custodian_clients = setup

    ir = compile_source(SAMPLE_SRC)
    pkg = build_package(ir)
    S_v = 42
    shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
    _install_and_activate(coordinator, custodian_clients, pkg, shares)

    x_val = 5
    expected = ((x_val + 7) ** 2) % PRIME

    # Each custodian evaluates on the plain input value
    results = []
    for i, cc in enumerate(custodian_clients):
        resp = cc.post(
            "/eval_share",
            json={
                "program_id": pkg.program_id,
                "request_id": "test-req-1",
                "input_shares": {"x": {"x": i + 1, "y": str(x_val)}},
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        results.append(int(str(body["y"])))

    # All custodians should produce the same deterministic result
    for r in results:
        assert r == expected


def test_fewer_than_k_shares_fail(setup):
    """Verify that K-1 shares do NOT produce the correct output."""
    _, custodian_clients = setup

    ir = compile_source(SAMPLE_SRC)
    pkg = build_package(ir)
    S_v = 42
    shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)

    pkg_dict = pkg.model_dump()
    for i, cc in enumerate(custodian_clients):
        x, y = shares[i]
        cc.post("/install", json={"program_package": pkg_dict, "share_x": str(x), "share_y": str(y)})

    x_val = 5
    input_shares = shamir.share(x_val, NUM_CUSTODIANS, THRESHOLD)

    # Gather only K-1 shares
    partial_output = []
    for i in range(THRESHOLD - 1):
        ix, iy = input_shares[i]
        resp = custodian_clients[i].post(
            "/eval_share",
            json={
                "program_id": pkg.program_id,
                "request_id": "test-partial",
                "input_shares": {"x": {"x": ix, "y": str(iy)}},
            },
        )
        body = resp.json()
        partial_output.append((body["x"], int(str(body["y"]))))

    if len(partial_output) > 0:
        # Reconstruction with < K points should give wrong answer
        wrong = shamir.reconstruct(partial_output)
        expected = ((x_val + 7) ** 2) % PRIME
        assert wrong != expected


def test_budget_enforcement(setup):
    coordinator, custodian_clients = setup

    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=2, max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)
    _install_and_activate(coordinator, custodian_clients, pkg, shares)

    # Mock the coordinator to call custodians in-process
    # For budget testing, we use the coordinator's /eval but need to patch HTTP calls.
    # Instead, test the policy engine directly.
    from quorumvm.coordinator.policy import PolicyEngine

    engine = PolicyEngine()
    engine.register(pkg.program_id, pkg.model_dump()["policy_manifest"])

    assert engine.check(pkg.program_id, "alice") is None
    assert engine.check(pkg.program_id, "alice") is None
    denial = engine.check(pkg.program_id, "alice")
    assert denial is not None
    assert "budget" in denial


def test_audit_chain(setup):
    coordinator, custodian_clients = setup

    ir = compile_source(SAMPLE_SRC)
    pkg = build_package(ir)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)
    _install_and_activate(coordinator, custodian_clients, pkg, shares)

    resp = coordinator.get("/audit")
    assert resp.status_code == 200
    audit = resp.json()
    assert audit["chain_valid"] is True
    assert len(audit["entries"]) >= 3  # install + approvals + activate
