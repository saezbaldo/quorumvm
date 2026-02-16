"""MVP signatures – HMAC-SHA256 per custodian.

Each custodian has a pre-shared key (see config.CUSTODIAN_KEYS).
A signature is HMAC(key, message).
"""

from __future__ import annotations

import hashlib
import hmac

from quorumvm.config import CUSTODIAN_KEYS


def sign(custodian_index: int, message: str) -> str:
    """Produce an HMAC-SHA256 hex signature for *message*."""
    key = CUSTODIAN_KEYS[custodian_index].encode()
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def verify(custodian_index: int, message: str, signature: str) -> bool:
    """Verify *signature* for *message* from custodian *custodian_index*."""
    expected = sign(custodian_index, message)
    return hmac.compare_digest(expected, signature)
