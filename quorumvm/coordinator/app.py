"""Coordinator FastAPI application.

The coordinator orchestrates:
- version activation (collect K approvals)
- evaluation with Beaver-triple-based secure multiplication
- policy enforcement & audit logging

Evaluation flow (P2P Beaver — Phase 8):
1. Shamir-share each input across N custodians.
2. Send shares to custodians via /eval_beaver.
3. If a custodian reports ``mul_pending``, the coordinator tells each
   custodian to broadcast its (ε_i, δ_i) shares to all peers via
   /beaver_shares (peer-to-peer).
4. The coordinator then tells each custodian to reconstruct ε, δ locally
   and compute its result share via /beaver_resolve_p2p.
5. The coordinator **never** sees the reconstructed ε or δ.
6. One designated custodian (index 0) folds ε*δ into its share, so plain
   Lagrange reconstruction of the output shares yields x*y directly.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Tuple

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from quorumvm.config import CUSTODIAN_URLS, DEFAULT_BEAVER_POOL_SIZE, NUM_CUSTODIANS, PRIME, THRESHOLD
from quorumvm.coordinator.audit import AuditLog
from quorumvm.coordinator.policy import PolicyEngine
from quorumvm.crypto import shamir, signatures
from quorumvm.crypto.beaver import generate_triples_for_program
from quorumvm.crypto import field

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
# program_id -> True if Beaver triples have been distributed
_beaver_ready: Dict[str, bool] = {}
# program_id -> remaining triple count (per mul node — they all share the same pool size)
_beaver_pool_remaining: Dict[str, int] = {}

_policy = PolicyEngine()
_audit = AuditLog()

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class InstallRequest(BaseModel):
    program_package: Dict[str, Any]
    # Optional: pre-generate Beaver triples during install
    generate_beaver: bool = True
    # Number of triples per mul node (consumed one per eval)
    beaver_pool_size: int = DEFAULT_BEAVER_POOL_SIZE


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
# Helper: find mul nodes in IR
# ---------------------------------------------------------------------------

def _find_mul_nodes(ir: dict) -> List[str]:
    """Return the IDs of all ``mul`` nodes in the IR."""
    return [n["id"] for n in ir["nodes"] if n["type"] == "mul"]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/install")
async def install(req: InstallRequest):
    """Install a program package on the coordinator and distribute Beaver triples."""
    pkg = req.program_package
    pid = pkg["program_id"]
    _packages[pid] = pkg
    _approvals[pid] = []
    _status[pid] = "PENDING"
    _policy.register(pid, pkg.get("policy_manifest", {}))
    _audit.append("install", {"program_id": pid, "version": pkg.get("version")})

    # Generate and distribute Beaver triples for mul nodes
    mul_nodes = _find_mul_nodes(pkg["ir"])
    if mul_nodes and req.generate_beaver:
        n = NUM_CUSTODIANS
        k = THRESHOLD
        pool_size = req.beaver_pool_size
        triples = generate_triples_for_program(mul_nodes, n, k, pool_size)

        # Distribute to each custodian
        async with httpx.AsyncClient(timeout=10.0) as client:
            for idx in range(n):
                # Build the triple-pool shares for this custodian
                # node_id -> list of {a, b, c}  (one per pool entry)
                custodian_triples: Dict[str, List[Dict[str, List[int]]]] = {}
                for node_id, triple_list in triples.items():
                    custodian_triples[node_id] = []
                    for triple_shares in triple_list:
                        cs = triple_shares.for_custodian(idx)
                        custodian_triples[node_id].append({
                            "a": list(cs["a"]),
                            "b": list(cs["b"]),
                            "c": list(cs["c"]),
                        })

                try:
                    url = f"{CUSTODIAN_URLS[idx]}/install_beaver"
                    resp = await client.post(url, json={
                        "program_id": pid,
                        "triple_shares": custodian_triples,
                    })
                    resp.raise_for_status()
                except Exception:
                    pass  # Will fail at eval time if too few custodians

        _beaver_ready[pid] = True
        _beaver_pool_remaining[pid] = pool_size
    else:
        _beaver_ready[pid] = len(mul_nodes) == 0  # No muls = ready
        _beaver_pool_remaining[pid] = 0

    return {
        "status": "installed",
        "program_id": pid,
        "beaver_ready": _beaver_ready[pid],
        "beaver_pool": _beaver_pool_remaining.get(pid, 0),
    }


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
    """Evaluate a program on given inputs using Beaver-triple secure multiplication.

    The inputs are Shamir-shared across custodians.  No custodian sees the
    plain input values.  Multiplications are resolved via the interactive
    Beaver protocol.
    """
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

    request_id = uuid.uuid4().hex
    n = NUM_CUSTODIANS
    k = THRESHOLD

    # ---- Shamir-share each input ----
    input_shares_per_custodian: Dict[int, Dict[str, Any]] = {
        idx: {} for idx in range(n)
    }
    for var_name, value in req.inputs.items():
        shares = shamir.share(value, n, k)
        for idx, (x, y) in enumerate(shares):
            input_shares_per_custodian[idx][var_name] = {
                "x": x,
                "y": str(y),
            }

    # ---- Check if program has mul nodes (needs Beaver) ----
    mul_nodes = _find_mul_nodes(_packages[pid]["ir"])
    use_beaver = len(mul_nodes) > 0 and _beaver_ready.get(pid, False)

    if not use_beaver:
        # ---------- Legacy path (no muls or no Beaver triples) ----------
        return await _eval_legacy(pid, request_id, req, input_shares_per_custodian, n, k)

    # ---- Check Beaver pool capacity ----
    remaining = _beaver_pool_remaining.get(pid, 0)
    if remaining <= 0:
        _audit.append(
            "eval_denied",
            {
                "program_id": pid,
                "identity_id": req.identity_id,
                "reason": "Beaver triple pool exhausted",
            },
        )
        raise HTTPException(
            409,
            "Beaver triple pool exhausted — replenish via POST /replenish_beaver",
        )

    # Decrement pool (consumed on use, one triple per mul node per eval)
    _beaver_pool_remaining[pid] = remaining - 1

    # ---------- Beaver-aware path ----------
    return await _eval_beaver(pid, request_id, req, input_shares_per_custodian, n, k, mul_nodes)


async def _eval_legacy(
    pid: str,
    request_id: str,
    req: EvalRequest,
    input_shares_per_custodian: Dict[int, Dict[str, Any]],
    n: int,
    k: int,
) -> dict:
    """Legacy evaluation: send shared inputs, collect output shares, reconstruct."""
    output_shares: List[Tuple[int, int]] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        for idx in range(n):
            url = f"{CUSTODIAN_URLS[idx]}/eval_share"
            payload = {
                "program_id": pid,
                "request_id": request_id,
                "input_shares": input_shares_per_custodian[idx],
            }
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                body = resp.json()
                output_shares.append((int(body["x"]), int(str(body["y"]))))
            except Exception:
                pass

    if len(output_shares) < k:
        raise HTTPException(503, f"Only {len(output_shares)}/{k} custodians responded")

    # Reconstruct output via Lagrange interpolation
    result = shamir.reconstruct(output_shares[:k])

    _audit.append(
        "eval_ok",
        {
            "program_id": pid,
            "identity_id": req.identity_id,
            "request_id": request_id,
            "result": result,
            "mode": "legacy",
        },
    )
    return {"result": result, "request_id": request_id}


async def _eval_beaver(
    pid: str,
    request_id: str,
    req: EvalRequest,
    input_shares_per_custodian: Dict[int, Dict[str, Any]],
    n: int,
    k: int,
    mul_nodes: List[str],
) -> dict:
    """Beaver-aware evaluation with P2P ε,δ exchange.

    The coordinator **never** reconstructs ε or δ.  Instead it tells
    custodians to broadcast their shares to each other (peer-to-peer)
    and then reconstruct locally.  One designated custodian (index 0)
    adds the ε*δ correction to its share so that plain Lagrange
    reconstruction of the output shares yields x*y directly.
    """

    async with httpx.AsyncClient(timeout=10.0) as client:
        # ---- Round 0: Start evaluation on all custodians ----
        responses: Dict[int, dict] = {}
        for idx in range(n):
            url = f"{CUSTODIAN_URLS[idx]}/eval_beaver"
            payload = {
                "program_id": pid,
                "request_id": request_id,
                "input_shares": input_shares_per_custodian[idx],
            }
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                responses[idx] = resp.json()
            except Exception:
                pass  # custodian down

        if len(responses) < k:
            raise HTTPException(503, f"Only {len(responses)}/{k} custodians responded")

        # ---- Interactive rounds: resolve mul nodes via P2P ----
        max_rounds = len(mul_nodes) * 2 + 1  # safety limit
        round_count = 0

        while round_count < max_rounds:
            round_count += 1

            # Check if any custodian has pending muls
            pending = {
                idx: r for idx, r in responses.items()
                if r.get("status") == "mul_pending"
            }
            if not pending:
                break  # All custodians are done

            # Collect node_ids that need resolution
            pending_node_ids: List[str] = []
            for idx, r in pending.items():
                for mr in r.get("mul_requests", []):
                    nid = mr["node_id"]
                    if nid not in pending_node_ids:
                        pending_node_ids.append(nid)

            # ---- P2P broadcast: each custodian sends its shares to all peers ----
            for sender_idx, r in pending.items():
                mul_reqs = r.get("mul_requests", [])
                shares_payload = [
                    {
                        "node_id": mr["node_id"],
                        "epsilon_share": mr["epsilon_share"],
                        "delta_share": mr["delta_share"],
                    }
                    for mr in mul_reqs
                ]
                sender_x = sender_idx + 1  # Shamir x-coordinate
                for receiver_idx in pending:
                    if receiver_idx == sender_idx:
                        continue  # already has own shares
                    url = f"{CUSTODIAN_URLS[receiver_idx]}/beaver_shares"
                    try:
                        await client.post(url, json={
                            "request_id": request_id,
                            "from_custodian": sender_x,
                            "shares": shares_payload,
                        })
                    except Exception:
                        pass

            # ---- Tell custodians to reconstruct ε,δ locally and resolve ----
            new_responses: Dict[int, dict] = {}
            for idx in pending:
                url = f"{CUSTODIAN_URLS[idx]}/beaver_resolve_p2p"
                try:
                    resp = await client.post(url, json={
                        "program_id": pid,
                        "request_id": request_id,
                        "mul_node_ids": pending_node_ids,
                    })
                    resp.raise_for_status()
                    new_responses[idx] = resp.json()
                except Exception:
                    pass

            # Merge responses
            for idx, r in new_responses.items():
                responses[idx] = r

        # ---- Collect output shares and reconstruct ----
        output_shares: List[Tuple[int, int]] = []
        for idx, r in responses.items():
            if r.get("status") == "done":
                output_shares.append((int(r["x"]), int(str(r["y"]))))

        if len(output_shares) < k:
            raise HTTPException(
                503,
                f"Only {len(output_shares)}/{k} custodians completed",
            )

        # Plain Lagrange reconstruction — no ε*δ correction needed!
        # Custodian 0 already folded ε*δ into its share.
        result = shamir.reconstruct(output_shares[:k])

    _audit.append(
        "eval_ok",
        {
            "program_id": pid,
            "identity_id": req.identity_id,
            "request_id": request_id,
            "result": result,
            "mode": "beaver_p2p",
        },
    )
    return {"result": result, "request_id": request_id}


class ReplenishRequest(BaseModel):
    program_id: str
    pool_size: int = DEFAULT_BEAVER_POOL_SIZE


@app.post("/replenish_beaver")
async def replenish_beaver(req: ReplenishRequest):
    """Generate and distribute fresh Beaver triples for an installed program.

    This is used when the original pool has been exhausted by evaluations.
    The new triples are *appended* to each custodian's pool.
    """
    pid = req.program_id
    if pid not in _packages:
        raise HTTPException(404, "Program not installed")

    mul_nodes = _find_mul_nodes(_packages[pid]["ir"])
    if not mul_nodes:
        return {"status": "no_mul_nodes", "program_id": pid}

    n = NUM_CUSTODIANS
    k = THRESHOLD
    triples = generate_triples_for_program(mul_nodes, n, k, req.pool_size)

    async with httpx.AsyncClient(timeout=10.0) as client:
        for idx in range(n):
            custodian_triples: Dict[str, List[Dict[str, List[int]]]] = {}
            for node_id, triple_list in triples.items():
                custodian_triples[node_id] = []
                for triple_shares in triple_list:
                    cs = triple_shares.for_custodian(idx)
                    custodian_triples[node_id].append({
                        "a": list(cs["a"]),
                        "b": list(cs["b"]),
                        "c": list(cs["c"]),
                    })
            try:
                url = f"{CUSTODIAN_URLS[idx]}/install_beaver"
                resp = await client.post(url, json={
                    "program_id": pid,
                    "triple_shares": custodian_triples,
                })
                resp.raise_for_status()
            except Exception:
                pass

    _beaver_pool_remaining[pid] = _beaver_pool_remaining.get(pid, 0) + req.pool_size
    _beaver_ready[pid] = True

    _audit.append("replenish_beaver", {
        "program_id": pid,
        "pool_size": req.pool_size,
        "total_remaining": _beaver_pool_remaining[pid],
    })

    return {
        "status": "replenished",
        "program_id": pid,
        "pool_remaining": _beaver_pool_remaining[pid],
    }


@app.get("/beaver_pool/{program_id}")
async def beaver_pool_status(program_id: str):
    """Check remaining Beaver triple pool capacity for a program."""
    if program_id not in _packages:
        raise HTTPException(404, "Program not installed")
    return {
        "program_id": program_id,
        "pool_remaining": _beaver_pool_remaining.get(program_id, 0),
        "beaver_ready": _beaver_ready.get(program_id, False),
    }


@app.get("/audit")
async def audit():
    """Return the full audit log."""
    return AuditResponse(entries=_audit.entries(), chain_valid=_audit.verify_chain())
