"""Anti-oracle policy enforcement.

Provides per-identity budget tracking and token-bucket rate limiting.
All state is in-memory (sufficient for MVP).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class _TokenBucket:
    """Simple token-bucket rate limiter."""

    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)

    def try_consume(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


class PolicyEngine:
    """Per-program, per-identity policy enforcement."""

    def __init__(self) -> None:
        # program_id -> policy params dict
        self._policies: Dict[str, dict] = {}
        # (program_id, identity_id) -> remaining budget
        self._budgets: Dict[tuple, int] = {}
        # (program_id, identity_id) -> token bucket
        self._rate_limiters: Dict[tuple, _TokenBucket] = {}

    # ---- registration ----

    def register(self, program_id: str, policy: dict) -> None:
        """Register policy parameters for a program."""
        self._policies[program_id] = policy

    # ---- enforcement ----

    def check(self, program_id: str, identity_id: str) -> str | None:
        """Return None if the request is allowed, or a reason string if denied."""
        policy = self._policies.get(program_id)
        if policy is None:
            return "program not registered"

        key = (program_id, identity_id)

        # --- budget ---
        budget_limit = policy.get("budget_per_identity", 0)
        cost = policy.get("cost_per_eval", 1)
        remaining = self._budgets.get(key, budget_limit)
        if remaining < cost:
            return f"budget exhausted (remaining={remaining}, cost={cost})"

        # --- rate limit ---
        max_per_min = policy.get("max_evals_per_minute", 60)
        bucket = self._rate_limiters.get(key)
        if bucket is None:
            bucket = _TokenBucket(
                capacity=float(max_per_min),
                refill_rate=max_per_min / 60.0,
                tokens=float(max_per_min),
            )
            self._rate_limiters[key] = bucket

        if not bucket.try_consume(1.0):
            return "rate limit exceeded"

        # deduct budget
        self._budgets[key] = remaining - cost
        return None  # allowed
