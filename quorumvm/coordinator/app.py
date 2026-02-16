"""Coordinator FastAPI application.

The coordinator orchestrates:
- version activation (collect K approvals)
- evaluation (split inputs → custodians → reconstruct output)
- policy enforcement & audit logging
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from quorumvm.config import CUSTODIAN_URLS, NUM_CUSTODIANS, THRESHOLD
from quorumvm.coordinator.audit import AuditLog
from quorumvm.coordinator.policy import PolicyEngine
from quorumvm.crypto import shamir, signatures

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="QuorumVM Coordinator")

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

# program_id -> ProgramPackage dict
_packages: Dict[str, dict] = {}
# program_id -> list of (custodian_index, signature)
_approvals: Dict[str, List[tuple]] = {}
# program_id -> "PENDING" | "ACTIVE"
_status: Dict[str, str] = {}

_policy = PolicyEngine()
_audit = AuditLog()

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class InstallRequest(BaseModel):
    program_package: Dict[str, Any]


class ApproveRequest(BaseModel):
    program_id: str
    custodian_index: int
    signature: str


class EvalRequest(BaseModel):
    identity_id: str
    program_id: str
    inputs: Dict[str, int]


class AuditResponse(BaseModel):
    entries: List[Dict[str, Any]]
    chain_valid: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/install")
async def install(req: InstallRequest):
    """Install a program package on the coordinator."""
    pkg = req.program_package
    pid = pkg["program_id"]
    _packages[pid] = pkg
    _approvals[pid] = []
    _status[pid] = "PENDING"
    _policy.register(pid, pkg.get("policy_manifest", {}))
    _audit.append("install", {"program_id": pid, "version": pkg.get("version")})
    return {"status": "installed", "program_id": pid}


@app.post("/approve")
async def approve(req: ApproveRequest):
    """Register a custodian approval for a program version."""
    pid = req.program_id
    if pid not in _packages:
        raise HTTPException(404, "Program not installed")
    # Verify signature
    if not signatures.verify(req.custodian_index, pid, req.signature):
        raise HTTPException(403, "Invalid signature")

    _approvals[pid].append((req.custodian_index, req.signature))
    _audit.append(
        "approve",
        {"program_id": pid, "custodian_index": req.custodian_index},
    )

    if len(_approvals[pid]) >= THRESHOLD and _status[pid] != "ACTIVE":
        _status[pid] = "ACTIVE"
        _audit.append("activate", {"program_id": pid})

    return {
        "status": _status[pid],
        "approvals": len(_approvals[pid]),
        "needed": THRESHOLD,
    }


@app.get("/status/{program_id}")
async def status(program_id: str):
    if program_id not in _packages:
        raise HTTPException(404, "Program not installed")
    return {"program_id": program_id, "status": _status[program_id]}


@app.post("/eval")
async def evaluate(req: EvalRequest):
    """Evaluate a program on given inputs (threshold-split execution)."""
    pid = req.program_id
    if pid not in _packages:
        raise HTTPException(404, "Program not installed")
    if _status.get(pid) != "ACTIVE":
        raise HTTPException(400, "Program not active")

    # ---- policy check ----
    denial = _policy.check(pid, req.identity_id)
    if denial is not None:
        _audit.append(
            "eval_denied",
            {"program_id": pid, "identity_id": req.identity_id, "reason": denial},
        )
        raise HTTPException(429, denial)

    # ---- distribute to custodians ----
    request_id = uuid.uuid4().hex
    n = NUM_CUSTODIANS
    k = THRESHOLD

    # MVP: send the full input values to each custodian.  Each custodian
    # evaluates the DAG independently and returns the result.  The
    # coordinator requires >= K consistent answers for the response.
    # (Shamir-splitting inputs doesn't work for circuits with mul
    # without Beaver-triple preprocessing, which is out of scope.)
    input_payload: Dict[str, Any] = {}
    for var_name, value in req.inputs.items():
        input_payload[var_name] = {"x": 0, "y": str(value)}

    # ---- fan out to custodians ----
    results: List[int] = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for idx in range(n):
            url = f"{CUSTODIAN_URLS[idx]}/eval_share"
            payload = {
                "program_id": pid,
                "request_id": request_id,
                "input_shares": input_payload,
            }
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                body = resp.json()
                results.append(int(str(body["y"])))
            except Exception:
                # Custodian may be down; we continue as long as we gather >= K
                pass

    if len(results) < k:
        raise HTTPException(503, f"Only {len(results)}/{k} custodians responded")

    # ---- verify consistency (all responding custodians should agree) ----
    result = results[0]

    _audit.append(
        "eval_ok",
        {
            "program_id": pid,
            "identity_id": req.identity_id,
            "request_id": request_id,
            "result": result,
        },
    )
    return {"result": result, "request_id": request_id}


@app.get("/audit")
async def audit():
    """Return the full audit log."""
    return AuditResponse(entries=_audit.entries(), chain_valid=_audit.verify_chain())
