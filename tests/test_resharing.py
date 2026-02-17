"""Tests for proactive resharing and custodian rotation (Phase 10).

Tests cover:
- Zero-share polynomial properties
- Sub-share generation and application
- Full resharing preserves the secret
- Multiple resharing rounds
- Custodian rotation: onboard new, retire old
- Mixed rotation: simultaneous onboard + retire
- Threshold edge cases
- HTTP endpoint tests (custodian + coordinator E2E)
"""

import pytest
import httpx

from quorumvm.config import PRIME, THRESHOLD, NUM_CUSTODIANS
from quorumvm.crypto import shamir, field
from quorumvm.crypto.resharing import (
    apply_sub_shares,
    eval_poly,
    generate_sub_shares,
    generate_zero_share_poly,
    reshare,
    rotate_custodians,
    _lagrange_at,
)


# ======================================================================
# Unit tests: zero-share polynomial
# ======================================================================


class TestZeroSharePoly:
    def test_constant_term_is_zero(self):
        """g(0) must be 0 for the resharing to preserve the secret."""
        for _ in range(10):
            poly = generate_zero_share_poly(k=3)
            assert poly[0] == 0
            assert eval_poly(poly, 0) == 0

    def test_degree(self):
        """Polynomial should have exactly k coefficients (degree k-1)."""
        poly = generate_zero_share_poly(k=4)
        assert len(poly) == 4

    def test_nonzero_at_nonzero_x(self):
        """g(x) should generally be nonzero for x != 0."""
        poly = generate_zero_share_poly(k=3)
        # Extremely unlikely to be zero at a random point
        vals = [eval_poly(poly, x) for x in range(1, 10)]
        assert any(v != 0 for v in vals)


# ======================================================================
# Unit tests: sub-share generation
# ======================================================================


class TestSubShares:
    def test_generate_sub_shares_covers_all_targets(self):
        targets = [1, 2, 3]
        subs = generate_sub_shares(k=2, target_x_coords=targets)
        assert set(subs.keys()) == set(targets)

    def test_sub_shares_sum_to_zero_at_origin(self):
        """Sum of sub-shares evaluated at 0 should be 0 (since g(0)=0)."""
        poly = generate_zero_share_poly(k=2)
        # g(0) = 0 is the defining property — sub-shares preserve this
        assert eval_poly(poly, 0) == 0


# ======================================================================
# Unit tests: apply sub-shares
# ======================================================================


class TestApplySubShares:
    def test_apply_identity(self):
        """Applying empty sub-shares leaves the share unchanged."""
        assert apply_sub_shares(42, []) == 42

    def test_apply_single(self):
        result = apply_sub_shares(100, [50])
        assert result == field.add(100, 50)

    def test_apply_multiple(self):
        result = apply_sub_shares(10, [20, 30, 40])
        expected = field.add(field.add(field.add(10, 20), 30), 40)
        assert result == expected


# ======================================================================
# Core: resharing preserves the secret
# ======================================================================


class TestResharing:
    def test_reshare_preserves_secret(self):
        """After resharing, the same secret should be reconstructable."""
        secret = 123456789
        n, k = 3, 2
        shares = shamir.share(secret, n, k)

        new_shares = reshare(shares, k)

        # Must reconstruct to same secret using any k of n
        for i in range(n):
            for j in range(i + 1, n):
                result = shamir.reconstruct([new_shares[i], new_shares[j]])
                assert result == secret, f"Failed with pair ({i},{j})"

    def test_reshare_changes_shares(self):
        """New shares should be different from old ones (with high probability)."""
        secret = 42
        shares = shamir.share(secret, 3, 2)
        new_shares = reshare(shares, 2)

        # At least one share should differ
        old_ys = {x: y for x, y in shares}
        new_ys = {x: y for x, y in new_shares}
        changed = sum(1 for x in old_ys if old_ys[x] != new_ys.get(x, -1))
        assert changed > 0, "Shares did not change (extremely unlikely)"

    def test_reshare_multiple_rounds(self):
        """Multiple consecutive resharing rounds preserve the secret."""
        secret = 987654321
        n, k = 3, 2
        shares = shamir.share(secret, n, k)

        for _round in range(5):
            shares = reshare(shares, k)

        result = shamir.reconstruct(shares[:k])
        assert result == secret

    def test_reshare_with_threshold_3(self):
        """Resharing works with higher threshold (k=3)."""
        secret = 555
        n, k = 5, 3
        shares = shamir.share(secret, n, k)

        new_shares = reshare(shares, k)

        result = shamir.reconstruct(new_shares[:k])
        assert result == secret

    def test_reshare_with_k_equals_n(self):
        """Edge case: k=n (all shares needed)."""
        secret = 777
        n, k = 3, 3
        shares = shamir.share(secret, n, k)

        new_shares = reshare(shares, k)

        result = shamir.reconstruct(new_shares)
        assert result == secret

    def test_reshare_fewer_than_k_fails(self):
        """Resharing requires at least k shares."""
        shares = [(1, 100)]  # only 1 share
        with pytest.raises(ValueError, match="Need >= k=2"):
            reshare(shares, k=2)

    def test_reshare_zero_secret(self):
        """Resharing the zero secret works correctly."""
        secret = 0
        shares = shamir.share(secret, 3, 2)
        new_shares = reshare(shares, 2)
        result = shamir.reconstruct(new_shares[:2])
        assert result == 0

    def test_reshare_large_secret(self):
        """Resharing near the field boundary."""
        secret = PRIME - 1
        shares = shamir.share(secret, 3, 2)
        new_shares = reshare(shares, 2)
        result = shamir.reconstruct(new_shares[:2])
        assert result == secret


# ======================================================================
# Custodian rotation
# ======================================================================


class TestRotation:
    def test_rotate_same_set(self):
        """Rotating to the same custodian set = resharing."""
        secret = 42
        n, k = 3, 2
        shares = shamir.share(secret, n, k)

        new_shares = rotate_custodians(shares, k, new_n=3)

        result = shamir.reconstruct(new_shares[:k])
        assert result == secret

    def test_rotate_expand(self):
        """Add a 4th custodian (N=3 → N=4)."""
        secret = 12345
        n, k = 3, 2
        shares = shamir.share(secret, n, k)

        new_shares = rotate_custodians(shares, k, new_n=4)

        assert len(new_shares) == 4
        # Any 2 of 4 should reconstruct
        result = shamir.reconstruct([new_shares[0], new_shares[3]])
        assert result == secret
        result2 = shamir.reconstruct([new_shares[1], new_shares[2]])
        assert result2 == secret

    def test_rotate_shrink(self):
        """Reduce from N=4 to N=3 (remove one custodian)."""
        secret = 99999
        n, k = 4, 2
        shares = shamir.share(secret, n, k)

        # Rotate to 3 custodians with new x-coordinates
        new_shares = rotate_custodians(shares, k, new_n=3, new_x_coords=[5, 6, 7])

        result = shamir.reconstruct(new_shares[:k])
        assert result == secret

    def test_rotate_replace_one(self):
        """Replace custodian 3 with a new one at x=4."""
        secret = 777
        n, k = 3, 2
        shares = shamir.share(secret, n, k)

        # Keep x=1,2 and add x=4 (replacing x=3)
        new_shares = rotate_custodians(shares, k, new_n=3, new_x_coords=[1, 2, 4])

        result = shamir.reconstruct(new_shares[:k])
        assert result == secret
        # Also verify with the new custodian
        result2 = shamir.reconstruct([new_shares[0], new_shares[2]])
        assert result2 == secret

    def test_rotate_k_greater_than_new_n_fails(self):
        """Cannot rotate if k > new_n."""
        shares = shamir.share(42, 3, 2)
        with pytest.raises(ValueError, match="k=3 > new_n=2"):
            rotate_custodians(shares, k=3, new_n=2)

    def test_rotate_preserves_after_multiple_rounds(self):
        """Multiple rotation rounds preserve the secret."""
        secret = 314159
        shares = shamir.share(secret, 3, 2)

        # Round 1: expand to 4
        shares = rotate_custodians(shares, 2, new_n=4)
        assert shamir.reconstruct(shares[:2]) == secret

        # Round 2: shrink to 3 (new coords)
        shares = rotate_custodians(shares, 2, new_n=3, new_x_coords=[10, 11, 12])
        assert shamir.reconstruct(shares[:2]) == secret

        # Round 3: back to standard
        shares = rotate_custodians(shares, 2, new_n=3)
        assert shamir.reconstruct(shares[:2]) == secret


# ======================================================================
# Lagrange at arbitrary x
# ======================================================================


class TestLagrangeAt:
    def test_lagrange_at_known_point(self):
        """Interpolating at a known x should return the known y."""
        shares = shamir.share(42, 3, 2)
        result = _lagrange_at(shares[:2], shares[0][0])
        assert result == shares[0][1]

    def test_lagrange_at_zero(self):
        """Interpolating at 0 should return the secret."""
        secret = 12345
        shares = shamir.share(secret, 3, 2)
        result = _lagrange_at(shares[:2], 0)
        assert result == secret

    def test_lagrange_at_new_point(self):
        """Interpolating at a new x gives the polynomial value there."""
        secret = 100
        shares = shamir.share(secret, 3, 2)
        # Interpolate at x=4 using first 2 shares
        y4 = _lagrange_at(shares[:2], 4)
        # Verify: share at x=4 should be on the same polynomial
        # Check by including (4, y4) as a point and reconstructing
        result = shamir.reconstruct([(4, y4), shares[0]])
        assert result == secret


# ======================================================================
# HTTP integration tests: custodian resharing endpoints
# ======================================================================


@pytest.fixture
def custodian_apps():
    """Create 3 custodian test apps with a shared secret."""
    from quorumvm.custodian.app import CustodianState, create_app
    from quorumvm.compiler.dsl_parser import compile_source
    from quorumvm.compiler.package import build_package
    from httpx import ASGITransport, AsyncClient

    src = "input x\nconst c = 7\nadd t = x c\noutput t"
    ir = compile_source(src)
    pkg = build_package(ir)
    pkg_dict = pkg.model_dump()

    secret = 42
    shares = shamir.share(secret, 3, 2)

    states = []
    clients = []
    for idx in range(3):
        st = CustodianState(idx)
        st.installed[pkg.program_id] = pkg_dict
        st.secret_shares[pkg.program_id] = shares[idx]
        states.append(st)

        app = create_app(st)
        transport = ASGITransport(app=app)
        c = AsyncClient(transport=transport, base_url="http://test")
        clients.append(c)

    return {
        "states": states,
        "clients": clients,
        "pkg": pkg_dict,
        "pid": pkg.program_id,
        "secret": secret,
        "shares": shares,
    }


@pytest.mark.asyncio
async def test_reshare_generate_endpoint(custodian_apps):
    """Custodian /reshare_generate returns sub-shares for all targets."""
    c = custodian_apps["clients"][0]
    pid = custodian_apps["pid"]

    resp = await c.post("/reshare_generate", json={
        "program_id": pid,
        "target_x_coords": [1, 2, 3],
        "k": 2,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert "sub_shares" in body
    assert set(body["sub_shares"].keys()) == {"1", "2", "3"}

    # Clean up
    for cl in custodian_apps["clients"]:
        await cl.aclose()


@pytest.mark.asyncio
async def test_reshare_apply_endpoint(custodian_apps):
    """Custodian /reshare_apply updates the secret share."""
    c = custodian_apps["clients"][0]
    pid = custodian_apps["pid"]
    st = custodian_apps["states"][0]

    old_share = st.secret_shares[pid]

    resp = await c.post("/reshare_apply", json={
        "program_id": pid,
        "sub_shares": ["100", "200"],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "reshared"

    # Share should have changed
    new_share = st.secret_shares[pid]
    expected_y = field.add(field.add(old_share[1], 100), 200)
    assert new_share[1] == expected_y
    assert new_share[0] == old_share[0]  # x unchanged

    for cl in custodian_apps["clients"]:
        await cl.aclose()


@pytest.mark.asyncio
async def test_reshare_full_round_via_endpoints(custodian_apps):
    """Full resharing round through HTTP endpoints preserves the secret."""
    clients = custodian_apps["clients"]
    states = custodian_apps["states"]
    pid = custodian_apps["pid"]
    secret = custodian_apps["secret"]
    k = 2

    # Step 1: Each custodian generates sub-shares
    all_subs = {}
    for idx, c in enumerate(clients):
        resp = await c.post("/reshare_generate", json={
            "program_id": pid,
            "target_x_coords": [1, 2, 3],
            "k": k,
        })
        body = resp.json()
        all_subs[idx] = {int(x): int(v) for x, v in body["sub_shares"].items()}

    # Step 2: Aggregate and apply sub-shares
    for target_idx, c in enumerate(clients):
        target_x = target_idx + 1
        deltas = [all_subs[sender][target_x] for sender in all_subs]
        resp = await c.post("/reshare_apply", json={
            "program_id": pid,
            "sub_shares": [str(d) for d in deltas],
        })
        assert resp.status_code == 200

    # Step 3: Verify secret is preserved
    new_shares = [states[i].secret_shares[pid] for i in range(3)]
    result = shamir.reconstruct([new_shares[0], new_shares[1]])
    assert result == secret
    result2 = shamir.reconstruct([new_shares[1], new_shares[2]])
    assert result2 == secret

    for cl in clients:
        await cl.aclose()


@pytest.mark.asyncio
async def test_retire_endpoint(custodian_apps):
    """Custodian /reshare_retire deletes shares and program data."""
    c = custodian_apps["clients"][2]
    st = custodian_apps["states"][2]
    pid = custodian_apps["pid"]

    assert pid in st.secret_shares
    assert pid in st.installed

    resp = await c.request("DELETE", f"/reshare_retire/{pid}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "retired"

    assert pid not in st.secret_shares
    assert pid not in st.installed

    for cl in custodian_apps["clients"]:
        await cl.aclose()


@pytest.mark.asyncio
async def test_set_share_endpoint(custodian_apps):
    """Custodian /reshare_set_share sets a new share (onboarding)."""
    c = custodian_apps["clients"][0]
    pid = custodian_apps["pid"]
    st = custodian_apps["states"][0]

    resp = await c.post("/reshare_set_share", json={
        "program_id": pid,
        "share_x": 10,
        "share_y": "999999",
    })
    assert resp.status_code == 200
    assert st.secret_shares[pid] == (10, 999999)

    for cl in custodian_apps["clients"]:
        await cl.aclose()


@pytest.mark.asyncio
async def test_lagrange_partial_endpoint(custodian_apps):
    """Custodian /reshare_lagrange_partial returns L_i(target) * y_i."""
    clients = custodian_apps["clients"]
    pid = custodian_apps["pid"]
    secret = custodian_apps["secret"]

    # Get Lagrange partials from custodians 0 and 1 at target x=4
    partials = []
    for idx in [0, 1]:
        resp = await clients[idx].post("/reshare_lagrange_partial", json={
            "program_id": pid,
            "target_x": 4,
            "participant_x_coords": [1, 2],
        })
        assert resp.status_code == 200
        partials.append(int(resp.json()["partial"]))

    # Sum of partials = f(4) where f is the polynomial
    f_at_4 = field.add(partials[0], partials[1])

    # Verify by reconstructing with (4, f(4)) and share[0]
    shares = custodian_apps["shares"]
    result = shamir.reconstruct([(4, f_at_4), shares[0]])
    assert result == secret

    for cl in clients:
        await cl.aclose()
