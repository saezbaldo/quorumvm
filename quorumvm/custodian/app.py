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

from quorumvm.config import CUSTODIAN_URLS, NUM_CUSTODIANS, PRIME, THRESHOLD
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


class BeaverP2PSharesRequest(BaseModel):
    """Receive ε,δ shares from another custodian for P2P reconstruction."""

    request_id: str
    from_custodian: int  # sender’s Shamir x-coordinate (1-based)
    shares: List[Dict[str, Any]]  # [{node_id, epsilon_share, delta_share}]


class BeaverResolveP2PRequest(BaseModel):
    """Coordinator tells custodian to reconstruct ε,δ locally and finish Round 2."""

    program_id: str
    request_id: str
    mul_node_ids: List[str]  # which mul nodes to resolve


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
        # P2P: request_id -> {node_id -> [(x_coord, eps_share, delta_share)]}
        self._p2p_shares: Dict[str, Dict[str, List[Tuple[int, int, int]]]] = {}
        # P2P: request_id -> {node_id -> (own_eps_share, own_delta_share)}
        self._own_mul_shares: Dict[str, Dict[str, Tuple[int, int]]] = {}


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
        """Legacy evaluation: plain values, no Beaver protocol.

        Supports multi-output: returns ``outputs`` dict alongside ``y``.
        """
        pid = req.program_id
        if pid not in state.installed:
            raise HTTPException(404, "Program not installed on this custodian")

        ir = state.installed[pid]["ir"]

        input_share_vals: Dict[str, int] = {}
        for var_name, point in req.input_shares.items():
            input_share_vals[var_name] = int(str(point["y"]))

        const_shares: Dict[str, int] = {}

        output_val = evaluate_ir(ir, input_share_vals, const_shares)

        # Multi-output support
        from quorumvm.custodian.executor import evaluate_ir_multi
        output_ids = ir.get("output_node_ids", [])
        outputs_dict: Dict[str, str] = {}
        if output_ids and len(output_ids) > 1:
            multi = evaluate_ir_multi(ir, input_share_vals, const_shares)
            outputs_dict = {k: str(v) for k, v in multi.items()}

        x = state.index + 1  # shares use x = 1..N
        resp: Dict[str, Any] = {"x": x, "y": str(output_val), "request_id": req.request_id}
        if outputs_dict:
            resp["outputs"] = outputs_dict
        return resp

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
            # Store own shares for P2P exchange
            own_shares: Dict[str, Tuple[int, int]] = {}
            for mr in mul_reqs:
                own_shares[mr.node_id] = (mr.epsilon_share, mr.delta_share)
            state._own_mul_shares[req.request_id] = own_shares
            # Initialize P2P collection with own shares
            p2p: Dict[str, List[Tuple[int, int, int]]] = {}
            x_coord = state.index + 1
            for mr in mul_reqs:
                p2p[mr.node_id] = [(x_coord, mr.epsilon_share, mr.delta_share)]
            state._p2p_shares[req.request_id] = p2p

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
        resp: Dict[str, Any] = {
            "status": "done",
            "x": x,
            "y": str(executor.output()),
            "request_id": req.request_id,
        }
        # Multi-output
        multi = executor.outputs()
        if len(multi) > 1:
            resp["outputs"] = {k: str(v) for k, v in multi.items()}
        return resp

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
        resp_r2: Dict[str, Any] = {
            "status": "done",
            "x": x,
            "y": str(output),
            "request_id": req.request_id,
        }
        multi_r2 = executor.outputs()
        if len(multi_r2) > 1:
            resp_r2["outputs"] = {k: str(v) for k, v in multi_r2.items()}
        return resp_r2

    @app.post("/beaver_shares")
    async def receive_beaver_shares(req: BeaverP2PSharesRequest):
        """Receive \u03b5,\u03b4 shares from another custodian (P2P exchange).

        Each custodian broadcasts its shares to all peers.  This endpoint
        collects them so the custodian can later reconstruct \u03b5,\u03b4 locally.
        """
        rid = req.request_id
        if rid not in state._p2p_shares:
            state._p2p_shares[rid] = {}

        for s in req.shares:
            nid = s["node_id"]
            if nid not in state._p2p_shares[rid]:
                state._p2p_shares[rid][nid] = []
            state._p2p_shares[rid][nid].append((
                req.from_custodian,
                int(str(s["epsilon_share"])),
                int(str(s["delta_share"])),
            ))

        return {"status": "received", "custodian": state.index}

    @app.post("/beaver_resolve_p2p")
    async def beaver_resolve_p2p(req: BeaverResolveP2PRequest):
        """Reconstruct \u03b5,\u03b4 locally from collected P2P shares and finish Round 2.

        The coordinator never sees the reconstructed \u03b5 or \u03b4.  One designated
        custodian (index 0) folds in the \u03b5*\u03b4 correction so that plain Lagrange
        reconstruction of the output shares yields x*y directly.
        """
        from quorumvm.crypto.beaver import custodian_mul_round2_with_correction

        executor = state._executors.get(req.request_id)
        if executor is None:
            raise HTTPException(404, "No active executor for this request_id")

        p2p = state._p2p_shares.get(req.request_id, {})
        k = THRESHOLD

        # Reconstruct ε,δ locally and build resolutions
        resolutions: List[MulResolution] = []
        for nid in req.mul_node_ids:
            shares_list = p2p.get(nid, [])
            if len(shares_list) < k:
                raise HTTPException(
                    503,
                    f"Not enough P2P shares for node {nid}: {len(shares_list)} < {k}",
                )
            eps_points = [(x, eps) for x, eps, _ in shares_list[:k]]
            delta_points = [(x, delta) for x, _, delta in shares_list[:k]]
            epsilon = shamir.reconstruct(eps_points)
            delta = shamir.reconstruct(delta_points)
            resolutions.append(MulResolution(nid, epsilon, delta))

        # Apply resolutions: each custodian locally computes z_i with ε*δ correction
        for res in resolutions:
            nid = res.node_id
            if nid not in executor.beaver_shares:
                raise ValueError(f"No Beaver shares for node '{nid}'")
            bshares = executor.beaver_shares[nid]
            z_share = custodian_mul_round2_with_correction(
                epsilon=res.epsilon,
                delta=res.delta,
                a_share_y=bshares["a"][1],
                b_share_y=bshares["b"][1],
                c_share_y=bshares["c"][1],
            )
            executor.wires[nid] = z_share
        executor._pending_muls.clear()

        # Continue stepping
        mul_reqs = executor.step()

        if mul_reqs:
            # More muls encountered — store own shares for next P2P round
            own_shares: Dict[str, Tuple[int, int]] = {}
            x_coord = state.index + 1
            new_p2p: Dict[str, List[Tuple[int, int, int]]] = {}
            for mr in mul_reqs:
                own_shares[mr.node_id] = (mr.epsilon_share, mr.delta_share)
                new_p2p[mr.node_id] = [(x_coord, mr.epsilon_share, mr.delta_share)]
            state._own_mul_shares[req.request_id] = own_shares
            state._p2p_shares[req.request_id] = new_p2p

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

        # DAG completed — clean up
        x = state.index + 1
        output = executor.output()
        del state._executors[req.request_id]
        state._p2p_shares.pop(req.request_id, None)
        state._own_mul_shares.pop(req.request_id, None)
        resp_p2p: Dict[str, Any] = {
            "status": "done",
            "x": x,
            "y": str(output),
            "request_id": req.request_id,
        }
        multi_p2p = executor.outputs()
        if len(multi_p2p) > 1:
            resp_p2p["outputs"] = {k: str(v) for k, v in multi_p2p.items()}
        return resp_p2p

    @app.get("/health")
    async def health():
        return {"custodian": state.index, "status": "ok"}

    return app
