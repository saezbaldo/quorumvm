#!/usr/bin/env python3
"""QuorumVM end-to-end demo.

Usage (after ``docker compose up --build``):
    python -m quorumvm.demo.run_demo

The script:
1. Compiles a sample DSL program to IR.
2. Builds a Program Package.
3. Generates secret S_v and Shamir shares for each custodian.
4. Installs the package + shares on every custodian.
5. Collects custodian approvals and sends them to the coordinator.
6. Activates the program (>= K approvals).
7. Runs evaluations and prints outputs.
8. Intentionally exceeds budget and rate limits to show enforcement.
9. Dumps the audit log.
"""

from __future__ import annotations

import os
import sys
import time

import httpx

from quorumvm.compiler.dsl_parser import compile_source
from quorumvm.compiler.package import PolicyManifest, build_package
from quorumvm.config import (
    CUSTODIAN_URLS,
    NUM_CUSTODIANS,
    PRIME,
    THRESHOLD,
)
from quorumvm.crypto import shamir
from quorumvm.crypto.field import reduce

# ---------- configurable base URLs (env vars → localhost fallback) ---------
COORDINATOR = os.environ.get("QUORUMVM_COORDINATOR_URL", "http://localhost:8000")
CUSTODIANS = [
    os.environ.get("QUORUMVM_CUSTODIAN_0_URL", "http://localhost:9100"),
    os.environ.get("QUORUMVM_CUSTODIAN_1_URL", "http://localhost:9101"),
    os.environ.get("QUORUMVM_CUSTODIAN_2_URL", "http://localhost:9102"),
]

# ---------- sample DSL program -------------------------------------------
SAMPLE_PROGRAM = """\
# f(x) = (x + 7)^2   over F_p
input x
const c = 7
add t = x c
mul y = t t
output y
"""


def banner(msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def main() -> None:
    client = httpx.Client(timeout=15.0)

    # ---- 1. Compile ----
    banner("1) Compile DSL → IR")
    ir = compile_source(SAMPLE_PROGRAM)
    print(f"   Nodes: {len(ir.nodes)}")
    print(f"   Output: {ir.output_node_id}")

    # ---- 2. Build package ----
    banner("2) Build Program Package")
    policy = PolicyManifest(
        cost_per_eval=1,
        budget_per_identity=5,
        max_evals_per_minute=60,
    )
    pkg = build_package(ir, version="1.0.0", policy=policy)
    print(f"   program_id = {pkg.program_id[:16]}…")

    # ---- 3. Generate secret and shares ----
    banner("3) Generate secret S_v and Shamir shares")
    S_v = 42  # MVP secret (field element)
    shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
    for i, (x, y) in enumerate(shares):
        print(f"   Custodian {i}: share=({x}, {y % 10**6}…)")

    # ---- 4. Install on custodians ----
    banner("4) Install package + shares on custodians")
    pkg_dict = pkg.model_dump()
    for i, url in enumerate(CUSTODIANS):
        x, y = shares[i]
        resp = client.post(
            f"{url}/install",
            json={
                "program_package": pkg_dict,
                "share_x": str(x),
                "share_y": str(y),
            },
        )
        resp.raise_for_status()
        print(f"   Custodian {i}: {resp.json()}")

    # ---- 5. Install on coordinator ----
    banner("5) Install package on coordinator")
    resp = client.post(f"{COORDINATOR}/install", json={"program_package": pkg_dict})
    resp.raise_for_status()
    print(f"   Coordinator: {resp.json()}")

    # ---- 6. Collect approvals (K of N) ----
    banner(f"6) Collect approvals (need {THRESHOLD} of {NUM_CUSTODIANS})")
    for i in range(THRESHOLD):
        # Ask custodian i to sign
        resp = client.post(f"{CUSTODIANS[i]}/approve", json={"program_id": pkg.program_id})
        resp.raise_for_status()
        approval = resp.json()
        print(f"   Custodian {i} signed: {approval['signature'][:16]}…")

        # Forward to coordinator
        resp = client.post(
            f"{COORDINATOR}/approve",
            json={
                "program_id": pkg.program_id,
                "custodian_index": approval["custodian_index"],
                "signature": approval["signature"],
            },
        )
        resp.raise_for_status()
        print(f"   Coordinator: {resp.json()}")

    # ---- 7. Check status ----
    resp = client.get(f"{COORDINATOR}/status/{pkg.program_id}")
    resp.raise_for_status()
    print(f"\n   Program status: {resp.json()['status']}")

    # ---- 8. Run evaluations ----
    banner("7) Evaluate program")
    identity = "alice"
    for x_val in [3, 10, 0]:
        resp = client.post(
            f"{COORDINATOR}/eval",
            json={
                "identity_id": identity,
                "program_id": pkg.program_id,
                "inputs": {"x": x_val},
            },
        )
        if resp.status_code == 200:
            result = resp.json()["result"]
            expected = ((x_val + 7) ** 2) % PRIME
            match = "✓" if result == expected else "✗"
            print(f"   f({x_val}) = {result}  (expected {expected}) {match}")
        else:
            print(f"   f({x_val}) → HTTP {resp.status_code}: {resp.text}")

    # ---- 9. Exhaust budget ----
    banner("8) Exhaust budget (budget_per_identity=5)")
    for attempt in range(5):
        resp = client.post(
            f"{COORDINATOR}/eval",
            json={
                "identity_id": identity,
                "program_id": pkg.program_id,
                "inputs": {"x": attempt},
            },
        )
        status = "ok" if resp.status_code == 200 else f"DENIED ({resp.status_code})"
        print(f"   Attempt {attempt + 1}: {status}")
        if resp.status_code != 200:
            print(f"     Reason: {resp.json().get('detail', resp.text)}")

    # ---- 10. Rate-limit demo (different identity) ----
    banner("9) Rate-limit demo (new identity, low limit)")
    # Re-install with a very tight rate limit to demonstrate
    tight_policy = PolicyManifest(
        cost_per_eval=1,
        budget_per_identity=100,
        max_evals_per_minute=2,
    )
    pkg2 = build_package(ir, version="2.0.0", policy=tight_policy)
    pkg2_dict = pkg2.model_dump()
    # Install + activate pkg2
    for i, url in enumerate(CUSTODIANS):
        x, y = shares[i]
        client.post(f"{url}/install", json={"program_package": pkg2_dict, "share_x": str(x), "share_y": str(y)})
    client.post(f"{COORDINATOR}/install", json={"program_package": pkg2_dict})
    for i in range(THRESHOLD):
        resp = client.post(f"{CUSTODIANS[i]}/approve", json={"program_id": pkg2.program_id})
        approval = resp.json()
        client.post(
            f"{COORDINATOR}/approve",
            json={
                "program_id": pkg2.program_id,
                "custodian_index": approval["custodian_index"],
                "signature": approval["signature"],
            },
        )

    identity2 = "bob"
    for attempt in range(5):
        resp = client.post(
            f"{COORDINATOR}/eval",
            json={
                "identity_id": identity2,
                "program_id": pkg2.program_id,
                "inputs": {"x": 1},
            },
        )
        status = "ok" if resp.status_code == 200 else f"DENIED ({resp.status_code})"
        print(f"   Rapid-fire {attempt + 1}: {status}")
        if resp.status_code != 200:
            print(f"     Reason: {resp.json().get('detail', resp.text)}")

    # ---- 11. Audit log ----
    banner("10) Audit log")
    resp = client.get(f"{COORDINATOR}/audit")
    resp.raise_for_status()
    audit = resp.json()
    print(f"   Entries: {len(audit['entries'])}")
    print(f"   Chain valid: {audit['chain_valid']}")
    for e in audit["entries"][-5:]:
        print(f"     [{e['event']}] {e['entry_hash'][:12]}… ← {e['prev_hash'][:12]}…")

    banner("DEMO COMPLETE")
    client.close()


if __name__ == "__main__":
    main()
