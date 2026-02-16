"""Custodian FastAPI application.

Each custodian instance holds:
- its index (from env var CUSTODIAN_INDEX)
- installed program packages
- Shamir shares of secrets (S_v) for each program

Endpoints:
- POST /install   – receive program package + share of S_v
- POST /approve   – sign program_id with HMAC key
- POST /eval_share – evaluate IR on input shares, return output share
"""

from __future__ import annotations

import os
from typing import Any, Dict, Union

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from quorumvm.config import NUM_CUSTODIANS, THRESHOLD
from quorumvm.crypto import shamir, signatures
from quorumvm.custodian.executor import evaluate_ir

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


class CustodianState:
    """Per-custodian mutable state."""

    def __init__(self, index: int) -> None:
        self.index = index
        self.installed: Dict[str, dict] = {}
        self.secret_shares: Dict[str, tuple] = {}


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
        pid = req.program_id
        if pid not in state.installed:
            raise HTTPException(404, "Program not installed on this custodian")

        ir = state.installed[pid]["ir"]

        # Build scalar input-share values for the executor
        input_share_vals: Dict[str, int] = {}
        for var_name, point in req.input_shares.items():
            input_share_vals[var_name] = int(str(point["y"]))

        # For constants, executor falls back to raw value (public constant)
        const_shares: Dict[str, int] = {}

        output_val = evaluate_ir(ir, input_share_vals, const_shares)

        # Return the share with the same x-coordinate as the input shares
        x = state.index + 1  # shares use x = 1..N
        return {"x": x, "y": str(output_val), "request_id": req.request_id}

    @app.get("/health")
    async def health():
        return {"custodian": state.index, "status": "ok"}

    return app
