"""Tests for Beaver triple secure multiplication.

Covers:
- Triple generation and verification
- Shamir sharing of triples
- The full Beaver protocol (custodian round 1 → reconstruct → round 2 → finalize)
- StepExecutor with Beaver triples on various circuits
- End-to-end Beaver eval through coordinator + custodian HTTP APIs
"""

from __future__ import annotations

import pytest

from quorumvm.config import NUM_CUSTODIANS, PRIME, THRESHOLD
from quorumvm.crypto import field, shamir
from quorumvm.crypto.beaver import (
    BeaverTriple,
    BeaverTripleShares,
    coordinator_finalize,
    custodian_mul_round1,
    custodian_mul_round2,
    generate_triple,
    generate_triple_shares,
    generate_triples_for_program,
)
from quorumvm.custodian.executor import MulResolution, StepExecutor


# =========================================================================
# 1. Triple generation
# =========================================================================


class TestTripleGeneration:
    def test_triple_verifies(self):
        t = generate_triple()
        assert t.verify(), "c should equal a * b mod p"

    def test_triples_are_random(self):
        t1 = generate_triple()
        t2 = generate_triple()
        assert (t1.a, t1.b) != (t2.a, t2.b), "Two triples should differ"

    def test_triple_components_in_field(self):
        t = generate_triple()
        assert 0 <= t.a < PRIME
        assert 0 <= t.b < PRIME
        assert 0 <= t.c < PRIME


# =========================================================================
# 2. Triple sharing
# =========================================================================


class TestTripleSharing:
    def test_shares_reconstruct_to_original(self):
        ts = generate_triple_shares(NUM_CUSTODIANS, THRESHOLD)
        # Reconstruct a, b, c from shares
        a = shamir.reconstruct(ts.a_shares[:THRESHOLD])
        b = shamir.reconstruct(ts.b_shares[:THRESHOLD])
        c = shamir.reconstruct(ts.c_shares[:THRESHOLD])
        assert c == field.mul(a, b), "Reconstructed c should = a*b"

    def test_per_custodian_shares(self):
        ts = generate_triple_shares(NUM_CUSTODIANS, THRESHOLD)
        for i in range(NUM_CUSTODIANS):
            cs = ts.for_custodian(i)
            assert "a" in cs and "b" in cs and "c" in cs
            # x-coordinates should be i+1
            assert cs["a"][0] == i + 1
            assert cs["b"][0] == i + 1
            assert cs["c"][0] == i + 1

    def test_generate_for_program(self):
        mul_ids = ["m1", "m2", "m3"]
        triples = generate_triples_for_program(mul_ids, NUM_CUSTODIANS, THRESHOLD)
        assert set(triples.keys()) == set(mul_ids)
        for nid, ts_list in triples.items():
            # Default pool_size=1 → list of one BeaverTripleShares
            assert isinstance(ts_list, list)
            assert len(ts_list) == 1
            assert len(ts_list[0].a_shares) == NUM_CUSTODIANS

    def test_generate_for_program_pool(self):
        """Pool mode: multiple triples per mul node."""
        mul_ids = ["m1", "m2"]
        pool_size = 4
        triples = generate_triples_for_program(
            mul_ids, NUM_CUSTODIANS, THRESHOLD, pool_size=pool_size,
        )
        for nid, ts_list in triples.items():
            assert len(ts_list) == pool_size
            for ts in ts_list:
                assert len(ts.a_shares) == NUM_CUSTODIANS


# =========================================================================
# 3. Beaver protocol (pure crypto, no HTTP)
# =========================================================================


class TestBeaverProtocol:
    """Test the Beaver multiplication protocol end-to-end in pure Python."""

    def _run_beaver_mul(self, x: int, y: int, n: int = 3, k: int = 2) -> int:
        """Run full Beaver protocol for z = x * y, return result."""
        x = field.reduce(x)
        y = field.reduce(y)

        # Share x and y
        x_shares = shamir.share(x, n, k)
        y_shares = shamir.share(y, n, k)

        # Generate Beaver triple and share it
        ts = generate_triple_shares(n, k)

        # --- Round 1: each custodian computes masked diffs ---
        eps_shares = []
        delta_shares = []
        for i in range(n):
            a_y = ts.a_shares[i][1]
            b_y = ts.b_shares[i][1]
            eps_i, delta_i = custodian_mul_round1(
                x_shares[i][1], y_shares[i][1], a_y, b_y,
            )
            eps_shares.append((i + 1, eps_i))
            delta_shares.append((i + 1, delta_i))

        # --- Coordinator reconstructs ε and δ ---
        epsilon = shamir.reconstruct(eps_shares[:k])
        delta = shamir.reconstruct(delta_shares[:k])

        # --- Round 2: each custodian computes result share ---
        z_shares = []
        for i in range(n):
            a_y = ts.a_shares[i][1]
            b_y = ts.b_shares[i][1]
            c_y = ts.c_shares[i][1]
            z_i = custodian_mul_round2(epsilon, delta, a_y, b_y, c_y)
            z_shares.append((i + 1, z_i))

        # --- Coordinator reconstructs and finalizes ---
        z_prime = shamir.reconstruct(z_shares[:k])
        result = coordinator_finalize(z_prime, epsilon, delta)
        return result

    def test_simple_mul(self):
        """3 * 7 = 21"""
        assert self._run_beaver_mul(3, 7) == 21

    def test_mul_zero(self):
        """x * 0 = 0"""
        assert self._run_beaver_mul(42, 0) == 0

    def test_mul_one(self):
        """x * 1 = x"""
        assert self._run_beaver_mul(42, 1) == 42

    def test_mul_large(self):
        """Large values should work in the field."""
        x = PRIME - 1  # -1 mod p
        y = PRIME - 2  # -2 mod p
        expected = field.mul(x, y)  # (-1)*(-2) = 2
        assert self._run_beaver_mul(x, y) == expected

    def test_mul_commutative(self):
        assert self._run_beaver_mul(13, 17) == self._run_beaver_mul(17, 13)

    def test_mul_associative(self):
        """(a * b) * c == a * (b * c)"""
        a, b, c = 5, 11, 23
        ab = self._run_beaver_mul(a, b)
        ab_c = self._run_beaver_mul(ab, c)

        bc = self._run_beaver_mul(b, c)
        a_bc = self._run_beaver_mul(a, bc)

        assert ab_c == a_bc

    def test_correctness_many_values(self):
        """Test correctness across many input pairs."""
        test_pairs = [
            (0, 0), (1, 1), (2, 3), (100, 200),
            (PRIME - 1, 2), (12345, 67890),
        ]
        for x, y in test_pairs:
            expected = field.mul(field.reduce(x), field.reduce(y))
            result = self._run_beaver_mul(x, y)
            assert result == expected, f"Failed for {x} * {y}: got {result}, expected {expected}"


# =========================================================================
# 4. StepExecutor with Beaver triples
# =========================================================================


class TestStepExecutor:
    """Test the DAG step-executor with Beaver protocol."""

    def _build_ir(self, source: str) -> dict:
        """Compile DSL source to IR dict."""
        from quorumvm.compiler.dsl_parser import compile_source
        return compile_source(source).to_dict()

    def test_linear_only_no_pause(self):
        """A program with only add/sub should complete in one step."""
        ir = self._build_ir("input x\nconst c = 5\nadd y = x c\noutput y")

        exec = StepExecutor(ir, {"x": 10}, {})
        mul_reqs = exec.step()
        assert mul_reqs == []
        assert exec.done
        assert exec.output() == field.add(10, 5)

    def test_mul_pauses_for_beaver(self):
        """A program with mul should pause and emit MulRequest."""
        ir = self._build_ir("input x\ninput y\nmul z = x y\noutput z")

        # Create Beaver shares for the mul node
        ts = generate_triple_shares(1, 1)  # single custodian for simplicity

        beaver = {
            "z": ts.for_custodian(0),
        }

        exec = StepExecutor(ir, {"x": 6, "y": 7}, {}, beaver)
        mul_reqs = exec.step()

        assert len(mul_reqs) == 1
        assert mul_reqs[0].node_id == "z"
        assert not exec.done

    def test_mul_resolve_gives_correct_output(self):
        """Full step-executor cycle with Beaver: pause → resolve → output."""
        ir = self._build_ir("input x\ninput y\nmul z = x y\noutput z")

        n, k = 3, 2
        x_val, y_val = 6, 7

        # Share inputs
        x_shares = shamir.share(x_val, n, k)
        y_shares = shamir.share(y_val, n, k)

        # Generate Beaver triple
        ts = generate_triple_shares(n, k)

        # Run step-executor on each custodian
        executors = []
        all_mul_reqs = []
        for i in range(n):
            beaver = {"z": ts.for_custodian(i)}
            exec = StepExecutor(
                ir,
                {"x": x_shares[i][1], "y": y_shares[i][1]},
                {},
                beaver,
            )
            mul_reqs = exec.step()
            executors.append(exec)
            all_mul_reqs.append(mul_reqs)

        # Coordinator reconstructs ε and δ
        eps_points = [(i + 1, all_mul_reqs[i][0].epsilon_share) for i in range(n)]
        delta_points = [(i + 1, all_mul_reqs[i][0].delta_share) for i in range(n)]
        epsilon = shamir.reconstruct(eps_points[:k])
        delta = shamir.reconstruct(delta_points[:k])

        # Round 2: resolve on each custodian
        for exec in executors:
            exec.resolve_muls([MulResolution("z", epsilon, delta)])
            remaining = exec.step()
            assert remaining == []
            assert exec.done

        # Reconstruct output
        output_shares = [(i + 1, executors[i].output()) for i in range(n)]
        z_prime = shamir.reconstruct(output_shares[:k])
        result = coordinator_finalize(z_prime, epsilon, delta)
        assert result == 42  # 6 * 7


# =========================================================================
# 5. End-to-end Beaver eval via HTTP (in-process)
# =========================================================================


class TestBeaverE2E:
    """Test Beaver eval through the full coordinator/custodian HTTP stack."""

    @pytest.fixture()
    def setup_services(self):
        """Set up in-process coordinator + custodians with mocked HTTP."""
        from unittest.mock import AsyncMock, patch
        from quorumvm.compiler.dsl_parser import compile_source
        from quorumvm.compiler.package import PolicyManifest, build_package
        from quorumvm.custodian.app import CustodianState, create_app as create_custodian
        from quorumvm.coordinator.app import app as coordinator_app
        from httpx import ASGITransport, AsyncClient

        # Compile a program with multiplication
        ir = compile_source(
            "input x\nconst c = 7\nadd t = x c\nmul y = t t\noutput y"
        )
        policy = PolicyManifest(cost_per_eval=1, budget_per_identity=10, max_evals_per_minute=60)
        pkg = build_package(ir, version="1.0.0", policy=policy)

        # Create custodian apps
        custodian_states = [CustodianState(i) for i in range(NUM_CUSTODIANS)]
        custodian_apps = [create_custodian(s) for s in custodian_states]

        return {
            "coordinator_app": coordinator_app,
            "custodian_apps": custodian_apps,
            "custodian_states": custodian_states,
            "pkg": pkg,
            "ir": ir,
        }

    @pytest.mark.asyncio
    async def test_beaver_eval_f_x_plus_7_squared(self, setup_services):
        """f(x) = (x+7)² via Beaver protocol. f(3) should = 100."""
        from httpx import ASGITransport, AsyncClient
        from unittest.mock import patch
        import quorumvm.coordinator.app as coord_module

        svc = setup_services
        coordinator_app = svc["coordinator_app"]
        custodian_apps = svc["custodian_apps"]
        pkg = svc["pkg"]

        # Reset coordinator state
        coord_module._packages.clear()
        coord_module._approvals.clear()
        coord_module._status.clear()
        coord_module._beaver_ready.clear()
        coord_module._beaver_epsilons.clear()
        coord_module._beaver_pool_remaining.clear()
        coord_module._policy = coord_module.PolicyEngine()
        coord_module._audit = coord_module.AuditLog()

        pkg_dict = pkg.model_dump()

        # Create ASGI transports for custodians
        custodian_transports = [
            ASGITransport(app=app) for app in custodian_apps
        ]
        custodian_clients = [
            AsyncClient(transport=t, base_url=f"http://custodian-{i}")
            for i, t in enumerate(custodian_transports)
        ]

        # Install on custodians with dummy shares (the secret S_v isn't
        # used in the computation — it's the Beaver triples that matter)
        S_v = 42
        shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
        for i, client in enumerate(custodian_clients):
            x, y = shares[i]
            resp = await client.post("/install", json={
                "program_package": pkg_dict,
                "share_x": str(x),
                "share_y": str(y),
            })
            assert resp.status_code == 200

        # We need to intercept coordinator's HTTP calls to custodians
        # and route them to in-process ASGI apps.
        original_post = AsyncClient.post

        async def mock_post(self_client, url: str, **kwargs):
            """Route coordinator→custodian calls to in-process apps."""
            for i in range(NUM_CUSTODIANS):
                for port in [9100 + i]:
                    prefix = f"http://custodian-{i}:{port}"
                    if url.startswith(prefix):
                        path = url[len(prefix):]
                        return await custodian_clients[i].post(path, **kwargs)
            # Fall through to real HTTP (shouldn't happen in tests)
            return await original_post(self_client, url, **kwargs)

        # Install on coordinator (which will also distribute Beaver triples)
        coord_transport = ASGITransport(app=coordinator_app)
        async with AsyncClient(transport=coord_transport, base_url="http://coordinator") as coord_client:
            with patch.object(AsyncClient, 'post', mock_post):
                resp = await coord_client.post("/install", json={
                    "program_package": pkg_dict,
                    "generate_beaver": True,
                })
                assert resp.status_code == 200
                body = resp.json()
                assert body["beaver_ready"] is True

                # Approve
                from quorumvm.crypto import signatures
                for i in range(THRESHOLD):
                    sig = signatures.sign(i, pkg.program_id)
                    resp = await coord_client.post("/approve", json={
                        "program_id": pkg.program_id,
                        "custodian_index": i,
                        "signature": sig,
                    })
                    assert resp.status_code == 200

                # Eval: f(3) = (3+7)² = 100
                resp = await coord_client.post("/eval", json={
                    "identity_id": "test-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 3},
                })
                assert resp.status_code == 200
                assert resp.json()["result"] == 100

        # Cleanup
        for c in custodian_clients:
            await c.aclose()

    @pytest.mark.asyncio
    async def test_beaver_eval_pure_linear_no_beaver(self, setup_services):
        """A pure linear program should work without Beaver triples."""
        from httpx import ASGITransport, AsyncClient
        from unittest.mock import patch
        import quorumvm.coordinator.app as coord_module
        from quorumvm.compiler.dsl_parser import compile_source
        from quorumvm.compiler.package import PolicyManifest, build_package

        # Reset coordinator state
        coord_module._packages.clear()
        coord_module._approvals.clear()
        coord_module._status.clear()
        coord_module._beaver_ready.clear()
        coord_module._beaver_epsilons.clear()
        coord_module._beaver_pool_remaining.clear()
        coord_module._policy = coord_module.PolicyEngine()
        coord_module._audit = coord_module.AuditLog()

        # Compile a linear-only program: f(x) = x + 10
        ir = compile_source("input x\nconst c = 10\nadd y = x c\noutput y")
        policy = PolicyManifest(cost_per_eval=1, budget_per_identity=10, max_evals_per_minute=60)
        pkg = build_package(ir, version="1.0.0", policy=policy)
        pkg_dict = pkg.model_dump()

        svc = setup_services
        custodian_apps = svc["custodian_apps"]

        custodian_transports = [ASGITransport(app=app) for app in custodian_apps]
        custodian_clients = [
            AsyncClient(transport=t, base_url=f"http://custodian-{i}")
            for i, t in enumerate(custodian_transports)
        ]

        shares = shamir.share(0, NUM_CUSTODIANS, THRESHOLD)
        for i, client in enumerate(custodian_clients):
            x, y = shares[i]
            resp = await client.post("/install", json={
                "program_package": pkg_dict,
                "share_x": str(x),
                "share_y": str(y),
            })
            assert resp.status_code == 200

        original_post = AsyncClient.post

        async def mock_post(self_client, url: str, **kwargs):
            for i in range(NUM_CUSTODIANS):
                prefix = f"http://custodian-{i}:{9100 + i}"
                if url.startswith(prefix):
                    path = url[len(prefix):]
                    return await custodian_clients[i].post(path, **kwargs)
            return await original_post(self_client, url, **kwargs)

        coord_transport = ASGITransport(app=svc["coordinator_app"])
        async with AsyncClient(transport=coord_transport, base_url="http://coordinator") as coord_client:
            with patch.object(AsyncClient, 'post', mock_post):
                resp = await coord_client.post("/install", json={
                    "program_package": pkg_dict,
                    "generate_beaver": True,
                })
                assert resp.status_code == 200

                from quorumvm.crypto import signatures
                for i in range(THRESHOLD):
                    sig = signatures.sign(i, pkg.program_id)
                    await coord_client.post("/approve", json={
                        "program_id": pkg.program_id,
                        "custodian_index": i,
                        "signature": sig,
                    })

                # f(5) = 5 + 10 = 15
                resp = await coord_client.post("/eval", json={
                    "identity_id": "test-user",
                    "program_id": pkg.program_id,
                    "inputs": {"x": 5},
                })
                assert resp.status_code == 200
                assert resp.json()["result"] == 15

        for c in custodian_clients:
            await c.aclose()


# =========================================================================
# 6. Beaver pool tests (consumption & exhaustion)
# =========================================================================


class TestBeaverPool:
    """Test that Beaver triples are consumed once per eval and pool exhaustion is enforced."""

    @pytest.fixture()
    def setup_services(self):
        """Set up in-process coordinator + custodians with mocked HTTP."""
        from quorumvm.compiler.dsl_parser import compile_source
        from quorumvm.compiler.package import PolicyManifest, build_package
        from quorumvm.custodian.app import CustodianState, create_app as create_custodian
        from quorumvm.coordinator.app import app as coordinator_app
        from httpx import ASGITransport, AsyncClient

        # Compile a program with multiplication: f(x)=(x+7)²
        ir = compile_source(
            "input x\nconst c = 7\nadd t = x c\nmul y = t t\noutput y"
        )
        policy = PolicyManifest(
            cost_per_eval=1, budget_per_identity=50, max_evals_per_minute=100,
        )
        pkg = build_package(ir, version="1.0.0", policy=policy)

        custodian_states = [CustodianState(i) for i in range(NUM_CUSTODIANS)]
        custodian_apps = [create_custodian(s) for s in custodian_states]

        return {
            "coordinator_app": coordinator_app,
            "custodian_apps": custodian_apps,
            "custodian_states": custodian_states,
            "pkg": pkg,
            "ir": ir,
        }

    async def _setup_program(self, svc, pool_size: int):
        """Install + activate a program with a given Beaver pool size."""
        from httpx import ASGITransport, AsyncClient
        from unittest.mock import patch
        import quorumvm.coordinator.app as coord_module

        coordinator_app = svc["coordinator_app"]
        custodian_apps = svc["custodian_apps"]
        pkg = svc["pkg"]

        # Reset coordinator state
        coord_module._packages.clear()
        coord_module._approvals.clear()
        coord_module._status.clear()
        coord_module._beaver_ready.clear()
        coord_module._beaver_epsilons.clear()
        coord_module._beaver_pool_remaining.clear()
        coord_module._policy = coord_module.PolicyEngine()
        coord_module._audit = coord_module.AuditLog()

        pkg_dict = pkg.model_dump()

        custodian_transports = [
            ASGITransport(app=app) for app in custodian_apps
        ]
        custodian_clients = [
            AsyncClient(transport=t, base_url=f"http://custodian-{i}")
            for i, t in enumerate(custodian_transports)
        ]

        # Install on custodians
        S_v = 42
        shares = shamir.share(S_v, NUM_CUSTODIANS, THRESHOLD)
        for i, client in enumerate(custodian_clients):
            x, y = shares[i]
            await client.post("/install", json={
                "program_package": pkg_dict,
                "share_x": str(x),
                "share_y": str(y),
            })

        # Mock HTTP for coordinator → custodian
        original_post = AsyncClient.post

        async def mock_post(self_client, url: str, **kwargs):
            for i in range(NUM_CUSTODIANS):
                prefix = f"http://custodian-{i}:{9100 + i}"
                if url.startswith(prefix):
                    path = url[len(prefix):]
                    return await custodian_clients[i].post(path, **kwargs)
            return await original_post(self_client, url, **kwargs)

        coord_transport = ASGITransport(app=coordinator_app)
        coord_client = AsyncClient(
            transport=coord_transport, base_url="http://coordinator",
        )

        with patch.object(AsyncClient, "post", mock_post):
            # Install with specific pool size
            resp = await coord_client.post("/install", json={
                "program_package": pkg_dict,
                "generate_beaver": True,
                "beaver_pool_size": pool_size,
            })
            assert resp.status_code == 200
            assert resp.json()["beaver_pool"] == pool_size

            # Approve
            from quorumvm.crypto import signatures
            for i in range(THRESHOLD):
                sig = signatures.sign(i, pkg.program_id)
                await coord_client.post("/approve", json={
                    "program_id": pkg.program_id,
                    "custodian_index": i,
                    "signature": sig,
                })

        return coord_client, custodian_clients, mock_post

    @pytest.mark.asyncio
    async def test_pool_allows_multiple_evals(self, setup_services):
        """A pool of size 3 should allow 3 evaluations."""
        from unittest.mock import patch
        from httpx import AsyncClient

        svc = setup_services
        coord_client, custodian_clients, mock_post = await self._setup_program(svc, pool_size=3)

        with patch.object(AsyncClient, "post", mock_post):
            for x_val in [3, 10, 0]:
                resp = await coord_client.post("/eval", json={
                    "identity_id": "pool-user",
                    "program_id": svc["pkg"].program_id,
                    "inputs": {"x": x_val},
                })
                assert resp.status_code == 200
                expected = (x_val + 7) ** 2
                assert resp.json()["result"] == expected

        for c in custodian_clients:
            await c.aclose()
        await coord_client.aclose()

    @pytest.mark.asyncio
    async def test_pool_exhaustion_returns_409(self, setup_services):
        """After exhausting the pool, further evals should return 409."""
        from unittest.mock import patch
        from httpx import AsyncClient

        svc = setup_services
        coord_client, custodian_clients, mock_post = await self._setup_program(svc, pool_size=2)

        with patch.object(AsyncClient, "post", mock_post):
            # Use both triples
            for x_val in [3, 10]:
                resp = await coord_client.post("/eval", json={
                    "identity_id": "exhaust-user",
                    "program_id": svc["pkg"].program_id,
                    "inputs": {"x": x_val},
                })
                assert resp.status_code == 200

            # Third eval should fail with 409
            resp = await coord_client.post("/eval", json={
                "identity_id": "exhaust-user",
                "program_id": svc["pkg"].program_id,
                "inputs": {"x": 5},
            })
            assert resp.status_code == 409

        for c in custodian_clients:
            await c.aclose()
        await coord_client.aclose()

    @pytest.mark.asyncio
    async def test_pool_replenish_allows_more_evals(self, setup_services):
        """After exhausting and replenishing, evals should work again."""
        from unittest.mock import patch
        from httpx import AsyncClient

        svc = setup_services
        coord_client, custodian_clients, mock_post = await self._setup_program(svc, pool_size=1)

        with patch.object(AsyncClient, "post", mock_post):
            # Use the one triple
            resp = await coord_client.post("/eval", json={
                "identity_id": "replenish-user",
                "program_id": svc["pkg"].program_id,
                "inputs": {"x": 3},
            })
            assert resp.status_code == 200
            assert resp.json()["result"] == 100

            # Should be exhausted now
            resp = await coord_client.post("/eval", json={
                "identity_id": "replenish-user",
                "program_id": svc["pkg"].program_id,
                "inputs": {"x": 3},
            })
            assert resp.status_code == 409

            # Replenish with 2 more triples
            resp = await coord_client.post("/replenish_beaver", json={
                "program_id": svc["pkg"].program_id,
                "pool_size": 2,
            })
            assert resp.status_code == 200
            assert resp.json()["pool_remaining"] == 2

            # Should work again
            resp = await coord_client.post("/eval", json={
                "identity_id": "replenish-user",
                "program_id": svc["pkg"].program_id,
                "inputs": {"x": 10},
            })
            assert resp.status_code == 200
            assert resp.json()["result"] == 289

        for c in custodian_clients:
            await c.aclose()
        await coord_client.aclose()

    @pytest.mark.asyncio
    async def test_pool_status_endpoint(self, setup_services):
        """The beaver_pool status endpoint should reflect remaining capacity."""
        from unittest.mock import patch
        from httpx import AsyncClient

        svc = setup_services
        coord_client, custodian_clients, mock_post = await self._setup_program(svc, pool_size=3)

        # Check initial pool
        resp = await coord_client.get(
            f"/beaver_pool/{svc['pkg'].program_id}"
        )
        assert resp.status_code == 200
        assert resp.json()["pool_remaining"] == 3

        with patch.object(AsyncClient, "post", mock_post):
            # Consume one
            await coord_client.post("/eval", json={
                "identity_id": "status-user",
                "program_id": svc["pkg"].program_id,
                "inputs": {"x": 3},
            })

        # Check decremented pool
        resp = await coord_client.get(
            f"/beaver_pool/{svc['pkg'].program_id}"
        )
        assert resp.status_code == 200
        assert resp.json()["pool_remaining"] == 2

        for c in custodian_clients:
            await c.aclose()
        await coord_client.aclose()

    @pytest.mark.asyncio
    async def test_different_evals_use_different_triples(self, setup_services):
        """Verify that consecutive evals consume different triples (pool decrements)."""
        from unittest.mock import patch
        from httpx import AsyncClient
        import quorumvm.coordinator.app as coord_module

        svc = setup_services
        coord_client, custodian_clients, mock_post = await self._setup_program(svc, pool_size=5)

        results = []
        with patch.object(AsyncClient, "post", mock_post):
            for x_val in [1, 2, 3, 4, 5]:
                resp = await coord_client.post("/eval", json={
                    "identity_id": "triple-user",
                    "program_id": svc["pkg"].program_id,
                    "inputs": {"x": x_val},
                })
                assert resp.status_code == 200
                results.append(resp.json()["result"])

        # All results should be correct
        expected = [(x + 7) ** 2 for x in [1, 2, 3, 4, 5]]
        assert results == expected

        # Pool should be exhausted
        remaining = coord_module._beaver_pool_remaining[svc["pkg"].program_id]
        assert remaining == 0

        for c in custodian_clients:
            await c.aclose()
        await coord_client.aclose()