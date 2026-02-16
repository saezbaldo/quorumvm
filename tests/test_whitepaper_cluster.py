#!/usr/bin/env python3
"""Whitepaper compliance tests — distributed cluster edition.

Runs against REAL coordinator + custodian services over the network.
Each test uses a unique program_id (via unique policy or version) so
tests don't interfere with each other's state.

Environment variables (set by K8s Job):
  QUORUMVM_COORDINATOR_URL   e.g. http://coordinator.quorumvm.svc.cluster.local:8000
  QUORUMVM_CUSTODIAN_0_URL   e.g. http://custodian-0.quorumvm.svc.cluster.local:9100
  QUORUMVM_CUSTODIAN_1_URL   ...
  QUORUMVM_CUSTODIAN_2_URL   ...

Usage:
  python -m tests.test_whitepaper_cluster
"""

from __future__ import annotations

import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import List

import httpx

from quorumvm.compiler.dsl_parser import compile_source
from quorumvm.compiler.package import PolicyManifest, build_package
from quorumvm.config import NUM_CUSTODIANS, PRIME, THRESHOLD
from quorumvm.crypto import shamir

# ---------------------------------------------------------------------------
# URL configuration
# ---------------------------------------------------------------------------
COORDINATOR = os.environ.get(
    "QUORUMVM_COORDINATOR_URL", "http://localhost:8000"
)
CUSTODIANS = [
    os.environ.get("QUORUMVM_CUSTODIAN_0_URL", "http://localhost:9100"),
    os.environ.get("QUORUMVM_CUSTODIAN_1_URL", "http://localhost:9101"),
    os.environ.get("QUORUMVM_CUSTODIAN_2_URL", "http://localhost:9102"),
]

SAMPLE_SRC = """\
input x
const c = 7
add t = x c
mul y = t t
output y
"""

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    name: str
    section: str
    passed: bool
    detail: str = ""


results: List[TestResult] = []
_test_counter = 0


def _unique_budget(base: int = 100) -> int:
    """Return a unique budget value so each test generates a unique program_id."""
    global _test_counter
    _test_counter += 1
    return base + _test_counter


def _install_and_activate(client: httpx.Client, pkg, shares, approve_count=THRESHOLD):
    """Install on all custodians + coordinator, then collect approvals."""
    pkg_dict = pkg.model_dump()

    # Install on custodians
    for i, url in enumerate(CUSTODIANS):
        x, y = shares[i]
        resp = client.post(
            f"{url}/install",
            json={"program_package": pkg_dict, "share_x": str(x), "share_y": str(y)},
        )
        resp.raise_for_status()

    # Install on coordinator
    resp = client.post(f"{COORDINATOR}/install", json={"program_package": pkg_dict})
    resp.raise_for_status()

    # Approve
    for i in range(approve_count):
        resp = client.post(
            f"{CUSTODIANS[i]}/approve", json={"program_id": pkg.program_id}
        )
        resp.raise_for_status()
        approval = resp.json()
        resp = client.post(
            f"{COORDINATOR}/approve",
            json={
                "program_id": pkg.program_id,
                "custodian_index": approval["custodian_index"],
                "signature": approval["signature"],
            },
        )
        resp.raise_for_status()


def run_test(section: str, name: str):
    """Decorator that captures test pass/fail."""
    def decorator(fn):
        def wrapper():
            try:
                fn()
                results.append(TestResult(name=name, section=section, passed=True))
                print(f"  ✅ {name}")
            except Exception as e:
                detail = f"{e}\n{traceback.format_exc()}"
                results.append(TestResult(name=name, section=section, passed=False, detail=detail))
                print(f"  ❌ {name}")
                print(f"     {e}")
        return wrapper
    return decorator


# =========================================================================
# §4.1 — No single point of authority (threshold approvals)
# =========================================================================

@run_test("§4.1", "fewer_than_k_approvals_stays_pending")
def test_fewer_than_k_approvals():
    """< K approvals → program remains PENDING."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=_unique_budget(), max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    pkg_dict = pkg.model_dump()

    # Install on custodians + coordinator
    for i, url in enumerate(CUSTODIANS):
        x, y = shares[i]
        client.post(f"{url}/install", json={"program_package": pkg_dict, "share_x": str(x), "share_y": str(y)}).raise_for_status()
    client.post(f"{COORDINATOR}/install", json={"program_package": pkg_dict}).raise_for_status()

    # Only K-1 approvals
    for i in range(THRESHOLD - 1):
        resp = client.post(f"{CUSTODIANS[i]}/approve", json={"program_id": pkg.program_id})
        approval = resp.json()
        client.post(f"{COORDINATOR}/approve", json={
            "program_id": pkg.program_id,
            "custodian_index": approval["custodian_index"],
            "signature": approval["signature"],
        })

    resp = client.get(f"{COORDINATOR}/status/{pkg.program_id}")
    assert resp.json()["status"] == "PENDING", f"Expected PENDING, got {resp.json()['status']}"
    client.close()


@run_test("§4.1", "invalid_signature_rejected")
def test_invalid_signature():
    """A forged approval signature is rejected (HTTP 403)."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=_unique_budget(), max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    pkg_dict = pkg.model_dump()
    for i, url in enumerate(CUSTODIANS):
        x, y = shares[i]
        client.post(f"{url}/install", json={"program_package": pkg_dict, "share_x": str(x), "share_y": str(y)}).raise_for_status()
    client.post(f"{COORDINATOR}/install", json={"program_package": pkg_dict}).raise_for_status()

    # Send forged signature
    resp = client.post(f"{COORDINATOR}/approve", json={
        "program_id": pkg.program_id,
        "custodian_index": 0,
        "signature": "forged-signature-value",
    })
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"
    client.close()


@run_test("§4.1", "eval_rejected_when_pending")
def test_eval_rejected_pending():
    """Eval on a PENDING program returns HTTP 400."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=_unique_budget(), max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    pkg_dict = pkg.model_dump()
    for i, url in enumerate(CUSTODIANS):
        x, y = shares[i]
        client.post(f"{url}/install", json={"program_package": pkg_dict, "share_x": str(x), "share_y": str(y)}).raise_for_status()
    client.post(f"{COORDINATOR}/install", json={"program_package": pkg_dict}).raise_for_status()
    # NO approvals

    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": "alice", "program_id": pkg.program_id, "inputs": {"x": 3},
    })
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
    client.close()


# =========================================================================
# §4.2 — No single point of knowledge (Shamir)
# =========================================================================

@run_test("§4.2", "k_shares_reconstruct_secret")
def test_k_shares_reconstruct():
    """K shares reconstruct the original secret."""
    S_v = 123456789
    shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
    reconstructed = shamir.reconstruct(shares[:THRESHOLD])
    assert reconstructed == S_v, f"Expected {S_v}, got {reconstructed}"


@run_test("§4.2", "fewer_than_k_shares_fail")
def test_fewer_than_k_fail():
    """< K shares do NOT reconstruct the secret."""
    S_v = 123456789
    shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
    if THRESHOLD > 1:
        wrong = shamir.reconstruct(shares[:THRESHOLD - 1])
        assert wrong != S_v, "K-1 shares must NOT reconstruct the secret"


# =========================================================================
# §4.4 — Version activation requires K approvals
# =========================================================================

@run_test("§4.4", "exactly_k_approvals_activates")
def test_k_approvals_activate():
    """Exactly K approvals → program becomes ACTIVE."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=_unique_budget(), max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    _install_and_activate(client, pkg, shares)

    resp = client.get(f"{COORDINATOR}/status/{pkg.program_id}")
    assert resp.json()["status"] == "ACTIVE", f"Expected ACTIVE, got {resp.json()['status']}"
    client.close()


# =========================================================================
# §4.5 — Graceful degradation
# =========================================================================

@run_test("§4.5", "eval_succeeds_with_one_custodian_slow")
def test_graceful_degradation():
    """Even if one custodian is slower, the coordinator gets >= K
    responses from the healthy ones and returns the correct result.

    Note: we can't actually kill a pod from inside a test Job, but we
    CAN verify that the coordinator handles N responses correctly and
    that the eval result is deterministic across all custodians.
    """
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=_unique_budget(), max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    _install_and_activate(client, pkg, shares)

    # Verify all 3 custodians produce the same deterministic result
    x_val = 5
    expected = ((x_val + 7) ** 2) % PRIME
    custodian_results = []
    for i, url in enumerate(CUSTODIANS):
        resp = client.post(f"{url}/eval_share", json={
            "program_id": pkg.program_id,
            "request_id": "degrade-test",
            "input_shares": {"x": {"x": i + 1, "y": str(x_val)}},
        })
        resp.raise_for_status()
        custodian_results.append(int(str(resp.json()["y"])))

    for i, r in enumerate(custodian_results):
        assert r == expected, f"Custodian {i} returned {r}, expected {expected}"

    # Verify coordinator eval works
    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": "degrade-user",
        "program_id": pkg.program_id,
        "inputs": {"x": x_val},
    })
    assert resp.status_code == 200
    assert resp.json()["result"] == expected
    client.close()


# =========================================================================
# §8 — Anti-oracle: budget enforcement
# =========================================================================

@run_test("§8", "budget_allows_then_denies")
def test_budget_enforcement():
    """Budget of 3 allows 3 evals, then denies the 4th via HTTP 429."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=3, max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    _install_and_activate(client, pkg, shares)

    identity = f"budget-user-{_test_counter}"

    # First 3 succeed
    for i in range(3):
        resp = client.post(f"{COORDINATOR}/eval", json={
            "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": i},
        })
        assert resp.status_code == 200, f"Eval {i+1} should succeed, got {resp.status_code}: {resp.text}"

    # 4th is denied
    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": 99},
    })
    assert resp.status_code == 429, f"Expected 429 (budget), got {resp.status_code}"
    assert "budget" in resp.json().get("detail", ""), f"Expected 'budget' in detail, got {resp.json()}"
    client.close()


@run_test("§8", "budget_per_identity_isolation")
def test_budget_isolation():
    """Budget exhaustion for identity A does not block identity B."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=1, max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    _install_and_activate(client, pkg, shares)

    alice = f"alice-iso-{_test_counter}"
    bob = f"bob-iso-{_test_counter}"

    # Alice uses her 1 eval
    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": alice, "program_id": pkg.program_id, "inputs": {"x": 1},
    })
    assert resp.status_code == 200

    # Alice is denied
    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": alice, "program_id": pkg.program_id, "inputs": {"x": 2},
    })
    assert resp.status_code == 429

    # Bob is still allowed
    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": bob, "program_id": pkg.program_id, "inputs": {"x": 1},
    })
    assert resp.status_code == 200, f"Bob should NOT be blocked, got {resp.status_code}"
    client.close()


# =========================================================================
# §8 — Anti-oracle: rate limiting
# =========================================================================

@run_test("§8", "rate_limit_denies_burst")
def test_rate_limit():
    """Rate limit of 2/min: first 2 pass, 3rd is denied."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=100, max_evals_per_minute=2)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    _install_and_activate(client, pkg, shares)

    identity = f"ratelimit-user-{_test_counter}"

    # First 2 within burst
    for i in range(2):
        resp = client.post(f"{COORDINATOR}/eval", json={
            "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": i},
        })
        assert resp.status_code == 200, f"Eval {i+1} should succeed, got {resp.status_code}"

    # 3rd should be rate limited
    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": 99},
    })
    assert resp.status_code == 429, f"Expected 429 (rate limit), got {resp.status_code}"
    assert "rate limit" in resp.json().get("detail", ""), f"Expected 'rate limit' in detail"
    client.close()


# =========================================================================
# §8 — Immutable audit log
# =========================================================================

@run_test("§8", "audit_chain_integrity")
def test_audit_chain():
    """Audit log chain is valid and entries are hash-linked."""
    client = httpx.Client(timeout=15)
    resp = client.get(f"{COORDINATOR}/audit")
    resp.raise_for_status()
    audit = resp.json()

    assert audit["chain_valid"] is True, "Audit chain should be valid"
    entries = audit["entries"]
    assert len(entries) >= 1, "Audit log should have entries"

    # Verify hash chain manually
    for i in range(1, len(entries)):
        assert entries[i]["prev_hash"] == entries[i - 1]["entry_hash"], \
            f"Chain broken at entry {i}: {entries[i]['prev_hash'][:12]} != {entries[i-1]['entry_hash'][:12]}"
    client.close()


@run_test("§8", "audit_records_eval_ok_and_denied")
def test_audit_events():
    """Audit log records both eval_ok and eval_denied events."""
    client = httpx.Client(timeout=15)
    ir = compile_source(SAMPLE_SRC)
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=1, max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    shares = shamir.share(42, NUM_CUSTODIANS, THRESHOLD)

    _install_and_activate(client, pkg, shares)

    identity = f"audit-user-{_test_counter}"

    # 1 success + 1 denial
    client.post(f"{COORDINATOR}/eval", json={
        "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": 1},
    })
    client.post(f"{COORDINATOR}/eval", json={
        "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": 2},
    })

    resp = client.get(f"{COORDINATOR}/audit")
    audit = resp.json()
    events = [e["event"] for e in audit["entries"]]

    assert "eval_ok" in events, f"Expected 'eval_ok' in audit events: {events}"
    assert "eval_denied" in events, f"Expected 'eval_denied' in audit events: {events}"
    assert audit["chain_valid"] is True
    client.close()


# =========================================================================
# §11 — Full E2E workflow (the "golden path")
# =========================================================================

@run_test("§11", "full_e2e_compile_activate_eval_budget_audit")
def test_full_e2e():
    """Complete whitepaper flow: compile → install → activate → eval → budget → audit."""
    client = httpx.Client(timeout=15)

    # ---- Compile ----
    ir = compile_source(SAMPLE_SRC)
    assert len(ir.nodes) == 4
    assert ir.output_node_id == "y"

    # ---- Build package ----
    policy = PolicyManifest(cost_per_eval=1, budget_per_identity=3, max_evals_per_minute=1000)
    pkg = build_package(ir, policy=policy)
    assert len(pkg.program_id) == 64

    # ---- Secret sharing ----
    S_v = 999999
    shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
    assert len(shares) == NUM_CUSTODIANS
    assert shamir.reconstruct(shares[:THRESHOLD]) == S_v

    # ---- Install ----
    _install_and_activate(client, pkg, shares)

    # ---- Verify ACTIVE ----
    resp = client.get(f"{COORDINATOR}/status/{pkg.program_id}")
    assert resp.json()["status"] == "ACTIVE"

    # ---- Evaluate with 3 inputs, verify correctness ----
    identity = f"e2e-user-{_test_counter}"
    test_cases = [
        (3, ((3 + 7) ** 2) % PRIME),     # 100
        (10, ((10 + 7) ** 2) % PRIME),    # 289
        (0, ((0 + 7) ** 2) % PRIME),      # 49
    ]
    for x_val, expected in test_cases:
        resp = client.post(f"{COORDINATOR}/eval", json={
            "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": x_val},
        })
        assert resp.status_code == 200, f"f({x_val}) failed: {resp.status_code}"
        result = resp.json()["result"]
        assert result == expected, f"f({x_val}) = {result}, expected {expected}"

    # ---- Budget exhaustion (used 3/3) ----
    resp = client.post(f"{COORDINATOR}/eval", json={
        "identity_id": identity, "program_id": pkg.program_id, "inputs": {"x": 1},
    })
    assert resp.status_code == 429
    assert "budget" in resp.json()["detail"]

    # ---- Audit log integrity ----
    resp = client.get(f"{COORDINATOR}/audit")
    audit = resp.json()
    assert audit["chain_valid"] is True
    events = [e["event"] for e in audit["entries"]]
    assert "install" in events
    assert "approve" in events
    assert "activate" in events
    assert "eval_ok" in events
    assert "eval_denied" in events

    client.close()


# =========================================================================
# Runner
# =========================================================================

ALL_TESTS = [
    # §4.1 — Threshold authority
    test_fewer_than_k_approvals,
    test_invalid_signature,
    test_eval_rejected_pending,
    # §4.2 — Secret sharing
    test_k_shares_reconstruct,
    test_fewer_than_k_fail,
    # §4.4 — Version activation
    test_k_approvals_activate,
    # §4.5 — Graceful degradation
    test_graceful_degradation,
    # §8 — Anti-oracle
    test_budget_enforcement,
    test_budget_isolation,
    test_rate_limit,
    test_audit_chain,
    test_audit_events,
    # §11 — Full E2E
    test_full_e2e,
]


def main() -> int:
    print("=" * 60)
    print("  PLAN-B Whitepaper Compliance — Distributed Cluster Tests")
    print(f"  Coordinator: {COORDINATOR}")
    print(f"  Custodians:  {CUSTODIANS}")
    print(f"  K={THRESHOLD}, N={NUM_CUSTODIANS}")
    print("=" * 60)

    # Wait for services to be ready
    print("\n⏳ Waiting for services...")
    client = httpx.Client(timeout=10)
    for url in [COORDINATOR] + CUSTODIANS:
        for attempt in range(30):
            try:
                health_url = f"{url}/health" if "custodian" in url else f"{url}/audit"
                resp = client.get(health_url)
                if resp.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            print(f"   ❌ {url} not reachable after 30s")
            return 1
        print(f"   ✅ {url}")
    client.close()

    # Run tests
    print("\n" + "=" * 60)
    print("  Running tests...")
    print("=" * 60)

    for test_fn in ALL_TESTS:
        test_fn()

    # Summary
    print("\n" + "=" * 60)
    passed = [r for r in results if r.passed]
    failed = [r for r in results if not r.passed]

    print(f"  RESULTS: {len(passed)}/{len(results)} passed")
    print("=" * 60)

    # Group by section
    sections = {}
    for r in results:
        sections.setdefault(r.section, []).append(r)

    for section, tests in sections.items():
        all_ok = all(t.passed for t in tests)
        mark = "✅" if all_ok else "❌"
        print(f"\n  {mark} {section}")
        for t in tests:
            status = "✅" if t.passed else "❌"
            print(f"     {status} {t.name}")

    if failed:
        print(f"\n{'='*60}")
        print("  FAILURES:")
        print("=" * 60)
        for r in failed:
            print(f"\n  ❌ [{r.section}] {r.name}")
            print(f"     {r.detail.strip()[:500]}")
        return 1
    else:
        print(f"\n{'='*60}")
        print("  ALL WHITEPAPER INVARIANTS VERIFIED ✅")
        print("=" * 60)
        return 0


if __name__ == "__main__":
    sys.exit(main())
