"""Custodian FastAPI application.

Each custodian instance holds:
- its index (from env var CUSTODIAN_INDEX)
- installed program packages
- Shamir shares of secrets (S_v) for each program
- Beaver triple shares for secure multiplication

Endpoints:
- POST /install         – receive program package + share of S_v
- POST /install_beaver  – receive Beaver triple shares for a program
- POST /approve         – sign program_id with HMAC key
- POST /eval_share      – evaluate IR on input shares, return output share
- POST /beaver_round1   – Beaver protocol Round 1: return masked diffs
- POST /beaver_round2   – Beaver protocol Round 2: compute result shares
- POST /eval_beaver     – full Beaver-aware step-by-step evaluation
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple, Union

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from quorumvm.config import NUM_CUSTODIANS, THRESHOLD
from quorumvm.crypto import shamir, signatures
from quorumvm.custodian.executor import (
    MulRequest,
    MulResolution,
    StepExecutor,
    evaluate_ir,
)

# ------ request models (module-level for Pydantic / FastAPI compat) ------


class CustodianInstallRequest(BaseModel):
    program_package: Dict[str, Any]
    share_x: Union[str, int]
    share_y: Union[str, int]


class CustodianApproveRequest(BaseModel):
    program_id: str


class CustodianEvalShareRequest(BaseModel):
    program_id: str
    request_id: str
    input_shares: Dict[str, Any]  # var_name -> {x, y}


class BeaverInstallRequest(BaseModel):
    """Install Beaver triple shares for a program.

    Supports both single triples (legacy) and pools.
    triple_shares maps node_id → either:
      - a list of {a, b, c} dicts (pool mode)
      - a single {a, b, c} dict  (legacy, auto-wrapped)
    """

    program_id: str
    # node_id -> list of {"a": [x, y], "b": [x, y], "c": [x, y]}
    # OR node_id -> {"a": [x, y], ...}  (single, backward compat)
    triple_shares: Dict[str, Any]


class BeaverEvalRequest(BaseModel):
    """Full Beaver-aware evaluation request."""

    program_id: str
    request_id: str
    input_shares: Dict[str, Any]  # var_name -> {x, y}


class BeaverRound2Request(BaseModel):
    """Beaver Round 2: coordinator sends back reconstructed ε, δ."""

    program_id: str
    request_id: str
    resolutions: List[Dict[str, Any]]  # [{node_id, epsilon, delta}, ...]


class CustodianState:
    """Per-custodian mutable state."""

    def __init__(self, index: int) -> None:
        self.index = index
        self.installed: Dict[str, dict] = {}
        self.secret_shares: Dict[str, tuple] = {}
        # program_id -> {node_id: [{"a": (x,y), "b": (x,y), "c": (x,y)}, ...]}
        # Each mul node has a FIFO pool; one triple is consumed per eval.
        self.beaver_pools: Dict[str, Dict[str, List[Dict[str, Tuple[int, int]]]]] = {}
        # request_id -> StepExecutor (for multi-round eval)
        self._executors: Dict[str, StepExecutor] = {}


def create_app(state: CustodianState | None = None) -> FastAPI:
    """Factory that creates a custodian app.

    If *state* is not provided a new ``CustodianState`` is created from
    the ``CUSTODIAN_INDEX`` environment variable.
    """
    if state is None:
        state = CustodianState(int(os.environ.get("CUSTODIAN_INDEX", "0")))

    app = FastAPI(title=f"QuorumVM Custodian {state.index}")

    @app.post("/install")
    async def install(req: CustodianInstallRequest):
        pid = req.program_package["program_id"]
        state.installed[pid] = req.program_package
        state.secret_shares[pid] = (int(req.share_x), int(req.share_y))
        return {"status": "installed", "custodian": state.index}

    @app.post("/install_beaver")
    async def install_beaver(req: BeaverInstallRequest):
        """Install Beaver triple shares for a program's mul nodes.

        Accepts a pool of triples per node (list) or a single triple
        (dict) for backward compatibility.  Triples are *appended*
        to the existing pool — this supports replenishment.
        """
        pid = req.program_id
        if pid not in state.beaver_pools:
            state.beaver_pools[pid] = {}

        total_installed = 0
        for node_id, raw in req.triple_shares.items():
            # Normalize: single dict → list of one
            entries = raw if isinstance(raw, list) else [raw]

            if node_id not in state.beaver_pools[pid]:
                state.beaver_pools[pid][node_id] = []

            for entry in entries:
                state.beaver_pools[pid][node_id].append({
                    "a": (int(entry["a"][0]), int(entry["a"][1])),
                    "b": (int(entry["b"][0]), int(entry["b"][1])),
                    "c": (int(entry["c"][0]), int(entry["c"][1])),
                })
                total_installed += 1

        return {
            "status": "beaver_installed",
            "custodian": state.index,
            "triples_installed": total_installed,
        }

    @app.post("/approve")
    async def approve(req: CustodianApproveRequest):
        sig = signatures.sign(state.index, req.program_id)
        return {
            "custodian_index": state.index,
            "program_id": req.program_id,
            "signature": sig,
        }

    @app.post("/eval_share")
    async def eval_share(req: CustodianEvalShareRequest):
        """Legacy evaluation: plain values, no Beaver protocol."""
        pid = req.program_id
        if pid not in state.installed:
            raise HTTPException(404, "Program not installed on this custodian")

        ir = state.installed[pid]["ir"]

        input_share_vals: Dict[str, int] = {}
        for var_name, point in req.input_shares.items():
            input_share_vals[var_name] = int(str(point["y"]))

        const_shares: Dict[str, int] = {}

        output_val = evaluate_ir(ir, input_share_vals, const_shares)

        x = state.index + 1  # shares use x = 1..N
        return {"x": x, "y": str(output_val), "request_id": req.request_id}

    @app.post("/eval_beaver")
    async def eval_beaver(req: BeaverEvalRequest):
        """Beaver-aware evaluation: Step through the DAG, pausing at mul nodes.

        Each evaluation **consumes** one triple per mul node from the pool.
        If the pool is empty, the coordinator should deny the request before
        reaching this endpoint.

        Returns either:
        - {"status": "mul_pending", "mul_requests": [...]}  if muls need resolution
        - {"status": "done", "x": ..., "y": ...}            if complete
        """
        pid = req.program_id
        if pid not in state.installed:
            raise HTTPException(404, "Program not installed on this custodian")

        ir = state.installed[pid]["ir"]

        # Build input shares
        input_share_vals: Dict[str, int] = {}
        for var_name, point in req.input_shares.items():
            input_share_vals[var_name] = int(str(point["y"]))

        const_shares: Dict[str, int] = {}

        # Pop one triple per mul node from the pool
        pool = state.beaver_pools.get(pid, {})
        beaver_for_eval: Dict[str, Dict[str, Tuple[int, int]]] = {}
        for node_id, triple_list in pool.items():
            if triple_list:
                beaver_for_eval[node_id] = triple_list.pop(0)

        executor = StepExecutor(ir, input_share_vals, const_shares, beaver_for_eval)
        state._executors[req.request_id] = executor

        # Step through the DAG
        mul_reqs = executor.step()

        if mul_reqs:
            return {
                "status": "mul_pending",
                "mul_requests": [
                    {
                        "node_id": mr.node_id,
                        "epsilon_share": str(mr.epsilon_share),
                        "delta_share": str(mr.delta_share),
                    }
                    for mr in mul_reqs
                ],
                "request_id": req.request_id,
            }

        # No muls or DAG completed
        x = state.index + 1
        return {
            "status": "done",
            "x": x,
            "y": str(executor.output()),
            "request_id": req.request_id,
        }

    @app.post("/beaver_round2")
    async def beaver_round2(req: BeaverRound2Request):
        """Beaver Round 2: receive (ε, δ) from coordinator, compute result shares.

        Then continue stepping through the DAG until another mul or done.
        """
        executor = state._executors.get(req.request_id)
        if executor is None:
            raise HTTPException(404, "No active executor for this request_id")

        # Apply resolutions
        resolutions = [
            MulResolution(
                node_id=r["node_id"],
                epsilon=int(str(r["epsilon"])),
                delta=int(str(r["delta"])),
            )
            for r in req.resolutions
        ]
        executor.resolve_muls(resolutions)

        # Continue stepping
        mul_reqs = executor.step()

        if mul_reqs:
            return {
                "status": "mul_pending",
                "mul_requests": [
                    {
                        "node_id": mr.node_id,
                        "epsilon_share": str(mr.epsilon_share),
                        "delta_share": str(mr.delta_share),
                    }
                    for mr in mul_reqs
                ],
                "request_id": req.request_id,
            }

        # DAG completed
        x = state.index + 1
        output = executor.output()
        # Clean up
        del state._executors[req.request_id]
        return {
            "status": "done",
            "x": x,
            "y": str(output),
            "request_id": req.request_id,
        }

    @app.get("/health")
    async def health():
        return {"custodian": state.index, "status": "ok"}

    return app
