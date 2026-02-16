"""Global configuration for QuorumVM MVP."""

import os

# ---------- Finite-field prime (256-bit Mersenne-friendly prime) ----------
# For MVP we use a reasonably large prime.  All arithmetic is mod PRIME.
PRIME = 2**127 - 1  # Mersenne prime M127

# ---------- Shamir parameters ----------
NUM_CUSTODIANS = 3   # N
THRESHOLD = 2        # K  (need >= K shares to reconstruct)

# ---------- Beaver triple pool ----------
DEFAULT_BEAVER_POOL_SIZE = 5   # triples per mul node, consumed one per eval

# ---------- Custodian network (used by coordinator) ----------
# In K8s the service DNS is  <svc>.<namespace>.svc.cluster.local
# Env var CUSTODIAN_URL_PREFIX overrides the base; default works for
# both Docker Compose and K8s (service names match).
_CUST_PREFIX = os.environ.get("CUSTODIAN_URL_PREFIX", "")  # e.g. "" or ".quorumvm.svc.cluster.local"
CUSTODIAN_URLS = [
    f"http://custodian-0{_CUST_PREFIX}:9100",
    f"http://custodian-1{_CUST_PREFIX}:9101",
    f"http://custodian-2{_CUST_PREFIX}:9102",
]

# ---------- Custodian HMAC keys (MVP – shared secrets) ----------
CUSTODIAN_KEYS = [
    "custodian-key-alpha",
    "custodian-key-beta",
    "custodian-key-gamma",
]

# ---------- Default policy limits ----------
DEFAULT_COST_PER_EVAL = 1
DEFAULT_BUDGET_PER_IDENTITY = 5
DEFAULT_MAX_EVALS_PER_MINUTE = 10
