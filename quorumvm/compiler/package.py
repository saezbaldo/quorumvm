"""Program Package builder.

A Program Package is a versioned, content-addressed JSON artifact that
bundles the compiled IR together with a secret manifest and a policy
manifest.  The ``program_id`` is the SHA-256 of the canonical JSON
representation of those three components.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from pydantic import BaseModel

from quorumvm.compiler.ir import IR
from quorumvm.config import (
    DEFAULT_BUDGET_PER_IDENTITY,
    DEFAULT_COST_PER_EVAL,
    DEFAULT_MAX_EVALS_PER_MINUTE,
)


class SecretManifest(BaseModel):
    """Describes secret parameters bound to the program version."""

    # For MVP a single field-element secret S_v.
    secret_name: str = "S_v"


class PolicyManifest(BaseModel):
    """Anti-oracle policy parameters."""

    cost_per_eval: int = DEFAULT_COST_PER_EVAL
    budget_per_identity: int = DEFAULT_BUDGET_PER_IDENTITY
    max_evals_per_minute: int = DEFAULT_MAX_EVALS_PER_MINUTE


class ProgramPackage(BaseModel):
    """Immutable versioned program package."""

    program_id: str  # SHA-256 hex digest
    version: str
    ir: Dict[str, Any]
    secret_manifest: Dict[str, Any]
    policy_manifest: Dict[str, Any]


def build_package(
    ir: IR,
    version: str = "1.0.0",
    policy: PolicyManifest | None = None,
    secret: SecretManifest | None = None,
) -> ProgramPackage:
    """Build a ``ProgramPackage`` from compiled IR and manifests."""
    if policy is None:
        policy = PolicyManifest()
    if secret is None:
        secret = SecretManifest()

    ir_dict = ir.to_dict()
    secret_dict = secret.model_dump()
    policy_dict = policy.model_dump()

    # Canonical JSON (sorted keys, no whitespace) for hashing
    canonical = json.dumps(
        {"ir": ir_dict, "policy_manifest": policy_dict, "secret_manifest": secret_dict},
        sort_keys=True,
        separators=(",", ":"),
    )
    program_id = hashlib.sha256(canonical.encode()).hexdigest()

    return ProgramPackage(
        program_id=program_id,
        version=version,
        ir=ir_dict,
        secret_manifest=secret_dict,
        policy_manifest=policy_dict,
    )
