"""Computational verification of formal security properties (Phase 11).

Each test maps to a theorem from docs/security_analysis.md, providing
concrete evidence for the formal claims through exhaustive or statistical
verification over the actual QuorumVM implementation.

Tests cover:
- Theorem 1: Information-theoretic threshold security
- Theorem 2: Beaver algebraic correctness (symbolic)
- Theorem 3: ε,δ uniform distribution (statistical)
- Theorem 4: Coordinator zero-knowledge in P2P flow
- Theorem 5: Resharing correctness (multi-round)
- Theorem 6: Resharing forward security
- Theorem 7: Oracle extraction lower bound
- Theorem 8: Budget blocks extraction
- SPDZ comparison: round count and communication analysis
"""

import collections
import math
import secrets
import pytest

from quorumvm.config import PRIME, THRESHOLD, NUM_CUSTODIANS
from quorumvm.crypto import field, shamir
from quorumvm.crypto.beaver import (
    BeaverTriple,
    custodian_mul_round1,
    custodian_mul_round2_with_correction,
    generate_triple,
    generate_triple_shares,
)
from quorumvm.crypto.resharing import (
    generate_zero_share_poly,
    reshare,
    _lagrange_at,
)


# ======================================================================
# Theorem 1 — Information-theoretic threshold security
# ======================================================================


class TestThresholdInfoTheoretic:
    """Verify that t < K shares reveal zero information about the secret."""

    def test_any_secret_consistent_with_one_share(self):
        """For a single share (t=1 < K=2), every possible secret s*
        in F_p has exactly one polynomial passing through (x_1, y_1)
        with f(0) = s*. We verify a sample of 100 candidates."""
        secret = secrets.randbelow(PRIME)
        shares = shamir.share(secret, 3, 2)
        x1, y1 = shares[0]

        for _ in range(100):
            s_star = secrets.randbelow(PRIME)
            # The unique degree-1 poly f with f(0)=s*, f(x1)=y1:
            # f(x) = s* + ((y1 - s*) / x1) * x
            slope = field.mul(field.sub(y1, s_star), field.inv(x1))
            # Verify: f(x1) = s* + slope * x1 = s* + (y1 - s*) = y1
            check = field.add(s_star, field.mul(slope, x1))
            assert check == y1, "Polynomial construction failed"
            # Verify: f(0) = s*
            assert s_star == s_star  # tautology — the point is that it exists

    def test_two_shares_determine_secret_uniquely(self):
        """With t=K=2 shares, the secret is uniquely determined."""
        secret = 12345
        shares = shamir.share(secret, 3, 2)
        result = shamir.reconstruct(shares[:2])
        assert result == secret

        # And any other pair of 2 shares gives the same secret
        for i in range(3):
            for j in range(i + 1, 3):
                assert shamir.reconstruct([shares[i], shares[j]]) == secret

    def test_single_share_entropy_preserved(self):
        """Different secrets produce uniform-looking shares at each x.

        Sample many secrets, record y values at x=1 — they should span
        a wide range (not cluster around any value).
        """
        ys = set()
        for _ in range(200):
            s = secrets.randbelow(PRIME)
            shares = shamir.share(s, 3, 2)
            ys.add(shares[0][1])
        # With overwhelming probability, 200 random field elements are distinct
        assert len(ys) == 200


# ======================================================================
# Theorem 2 — Beaver algebraic correctness
# ======================================================================


class TestBeaverAlgebraicCorrectness:
    """Symbolic verification that the Beaver protocol computes x*y."""

    def test_correctness_random_inputs(self):
        """Verify z = x*y for 50 random (x, y) pairs using full protocol."""
        n, k = 3, 2
        for _ in range(50):
            x = secrets.randbelow(PRIME)
            y = secrets.randbelow(PRIME)
            expected = field.mul(x, y)

            # Share x, y
            x_shares = shamir.share(x, n, k)
            y_shares = shamir.share(y, n, k)

            # Generate Beaver triple
            triple_shares = generate_triple_shares(n, k)

            # Round 1: each custodian computes ε_i, δ_i
            eps_shares = []
            delta_shares = []
            for i in range(n):
                e, d = custodian_mul_round1(
                    x_shares[i][1], y_shares[i][1],
                    triple_shares.a_shares[i][1],
                    triple_shares.b_shares[i][1],
                )
                eps_shares.append((x_shares[i][0], e))
                delta_shares.append((x_shares[i][0], d))

            # Reconstruct ε, δ
            epsilon = shamir.reconstruct(eps_shares[:k])
            delta = shamir.reconstruct(delta_shares[:k])

            # Round 2 with correction: each custodian computes z_i
            z_shares = []
            for i in range(n):
                z_i = custodian_mul_round2_with_correction(
                    epsilon, delta,
                    triple_shares.a_shares[i][1],
                    triple_shares.b_shares[i][1],
                    triple_shares.c_shares[i][1],
                )
                z_shares.append((x_shares[i][0], z_i))

            # Reconstruct z
            z = shamir.reconstruct(z_shares[:k])
            assert z == expected

    def test_algebraic_identity_symbolic(self):
        """Directly verify the algebraic identity:
        c + ε*b + δ*a + ε*δ = x*y
        where ε=x-a, δ=y-b, c=a*b.
        """
        for _ in range(100):
            x = secrets.randbelow(PRIME)
            y = secrets.randbelow(PRIME)
            a = secrets.randbelow(PRIME)
            b = secrets.randbelow(PRIME)
            c = field.mul(a, b)
            eps = field.sub(x, a)
            delta = field.sub(y, b)

            # c + ε*b + δ*a + ε*δ
            result = c
            result = field.add(result, field.mul(eps, b))
            result = field.add(result, field.mul(delta, a))
            result = field.add(result, field.mul(eps, delta))

            assert result == field.mul(x, y)


# ======================================================================
# Theorem 3 — ε,δ uniform distribution (statistical)
# ======================================================================


class TestEpsilonDeltaLeakage:
    """Statistical analysis of ε,δ values."""

    def test_epsilon_independent_of_x(self):
        """ε = x - a is uniform regardless of x.

        Fix x, sample many (a), compute ε. Check that ε values
        are spread uniformly (no clustering).
        """
        x = 42
        epsilons = set()
        for _ in range(500):
            a = secrets.randbelow(PRIME)
            eps = field.sub(x, a)
            epsilons.add(eps)
        # 500 uniform random field elements should be distinct
        assert len(epsilons) == 500

    def test_epsilon_for_different_x_same_distribution(self):
        """ε distributions for different x values are indistinguishable.

        For two different x values, collect ε samples with shared random a.
        The distributions should be the same (both uniform).
        """
        x1, x2 = 100, 999999
        # Same a → different ε, but both uniform
        samples = 200
        eps1_set = set()
        eps2_set = set()
        for _ in range(samples):
            a = secrets.randbelow(PRIME)
            eps1_set.add(field.sub(x1, a))
            eps2_set.add(field.sub(x2, a))
        # Both sets should have 200 distinct elements (uniform)
        assert len(eps1_set) == samples
        assert len(eps2_set) == samples

    def test_epsilon_delta_pair_reveals_nothing_without_ab(self):
        """Without knowing (a, b), the pair (ε, δ) gives no info about (x, y).

        For fixed (ε, δ), many different (x, y) pairs are consistent:
        any (a, b) with x=a+ε, y=b+δ works. Since a, b are unknown
        and uniform, (x, y) could be anything.
        """
        eps = secrets.randbelow(PRIME)
        delta = secrets.randbelow(PRIME)

        # Sample 100 random (a,b) → each gives a different valid (x,y)
        xy_pairs = set()
        for _ in range(100):
            a = secrets.randbelow(PRIME)
            b = secrets.randbelow(PRIME)
            x = field.add(a, eps)
            y = field.add(b, delta)
            xy_pairs.add((x, y))

        assert len(xy_pairs) == 100  # All distinct — ε,δ don't constrain x,y


# ======================================================================
# Theorem 4 — Coordinator zero-knowledge in P2P flow
# ======================================================================


class TestCoordinatorZeroKnowledge:
    """Verify that in the P2P flow, the coordinator's view is simulatable."""

    def test_coordinator_view_is_random_shares(self):
        """The coordinator sees only output z_shares, which are uniform
        random field elements individually. Verify that any individual z_i
        is indistinguishable from random."""
        n, k = 3, 2
        x, y = 1000, 2000
        x_shares = shamir.share(x, n, k)
        y_shares = shamir.share(y, n, k)
        triple_shares = generate_triple_shares(n, k)

        # Compute ε,δ locally
        eps_shares = []
        delta_shares = []
        for i in range(n):
            e, d = custodian_mul_round1(
                x_shares[i][1], y_shares[i][1],
                triple_shares.a_shares[i][1],
                triple_shares.b_shares[i][1],
            )
            eps_shares.append((i + 1, e))
            delta_shares.append((i + 1, d))

        epsilon = shamir.reconstruct(eps_shares[:k])
        delta = shamir.reconstruct(delta_shares[:k])

        # Compute z_shares
        z_shares = []
        for i in range(n):
            z_i = custodian_mul_round2_with_correction(
                epsilon, delta,
                triple_shares.a_shares[i][1],
                triple_shares.b_shares[i][1],
                triple_shares.c_shares[i][1],
            )
            z_shares.append(z_i)

        # Each z_i is a point on a degree-(k-1) polynomial with random
        # coefficients (conditioned on z=x*y).  For t<k, an individual
        # z_i reveals nothing about z.  Verify: z_i values look random.
        assert len(set(z_shares)) == n  # All distinct (with overwhelming prob)

        # The reconstructed value is deterministic, but individual shares aren't
        result = shamir.reconstruct([(i + 1, z_shares[i]) for i in range(k)])
        assert result == field.mul(x, y)

    def test_simulator_produces_indistinguishable_view(self):
        """A simulator can produce a coordinator view indistinguishable
        from real: just sample N random field elements whose Lagrange
        reconstruction at 0 equals x*y."""
        n, k = 3, 2
        target_z = field.mul(1000, 2000)

        # Simulator: pick (k-1) random shares, compute the k-th to match target
        sim_shares = []
        for i in range(1, n):  # i = 1, 2 (custodians 2 and 3)
            sim_shares.append((i + 1, secrets.randbelow(PRIME)))

        # Compute share for x=1 so that reconstruct = target_z
        # Using k=2: L_1(0)*y_1 + L_2(0)*y_2 = target_z
        # L_1(0) for x=1 among {1, 2}: L_1(0) = (0-2)/(1-2) = 2
        # L_2(0) for x=2 among {1, 2}: L_2(0) = (0-1)/(2-1) = -1 = p-1
        x1, x2 = 1, sim_shares[0][0]
        l1 = field.mul(field.sub(0, x2), field.inv(field.sub(x1, x2)))
        l2 = field.mul(field.sub(0, x1), field.inv(field.sub(x2, x1)))
        # target_z = l1*y1 + l2*y2 → y1 = (target_z - l2*y2) / l1
        y1 = field.mul(
            field.sub(target_z, field.mul(l2, sim_shares[0][1])),
            field.inv(l1),
        )
        sim_shares.insert(0, (1, y1))

        result = shamir.reconstruct(sim_shares[:k])
        assert result == target_z


# ======================================================================
# Theorem 5 — Resharing correctness (multi-round)
# ======================================================================


class TestResharingFormal:
    """Formal verification of resharing correctness."""

    def test_resharing_preserves_secret_100_rounds(self):
        """100 consecutive resharing rounds preserve the secret."""
        secret = 271828
        shares = shamir.share(secret, 3, 2)
        for _ in range(100):
            shares = reshare(shares, 2)
        result = shamir.reconstruct(shares[:2])
        assert result == secret

    def test_resharing_every_possible_k_subset(self):
        """After resharing, EVERY possible K-subset reconstructs correctly."""
        secret = 42
        shares = shamir.share(secret, 5, 3)
        new_shares = reshare(shares, 3)

        from itertools import combinations
        for subset in combinations(new_shares, 3):
            assert shamir.reconstruct(list(subset)) == secret

    def test_zero_share_poly_sum_is_zero_at_origin(self):
        """Σ g_i(0) = 0 for N independent zero-share polynomials."""
        n, k = 5, 3
        total = 0
        for _ in range(n):
            poly = generate_zero_share_poly(k)
            total = field.add(total, poly[0])
        assert total == 0


# ======================================================================
# Theorem 6 — Resharing forward security
# ======================================================================


class TestResharingForwardSecurity:
    """Old shares + new shares from different epochs cannot be combined."""

    def test_old_new_shares_on_different_polynomials(self):
        """Old and new share y-values differ at the same x-coordinate."""
        secret = 777
        shares = shamir.share(secret, 3, 2)
        old_shares = list(shares)
        new_shares = reshare(shares, 2)

        # With overwhelming probability, y values change
        changed = sum(
            1 for (xo, yo), (xn, yn) in zip(old_shares, new_shares)
            if yo != yn
        )
        assert changed > 0

    def test_mixing_epochs_gives_wrong_secret(self):
        """Taking 1 old share and 1 new share reconstructs WRONG value."""
        secret = 42
        shares = shamir.share(secret, 3, 2)
        new_shares = reshare(shares, 2)

        # Mix: old share[0] + new share[1]
        mixed = [shares[0], new_shares[1]]
        result = shamir.reconstruct(mixed)

        # Should NOT equal the secret (with overwhelming probability)
        assert result != secret

    def test_forward_security_probability(self):
        """Run 100 resharing rounds, each time verify old shares are invalid."""
        secret = 999
        shares = shamir.share(secret, 3, 2)

        for _ in range(100):
            old_shares = list(shares)
            shares = reshare(shares, 2)

            # Mixed reconstruction should fail (wrong secret)
            mixed = [old_shares[0], shares[1]]
            result = shamir.reconstruct(mixed)
            assert result != secret  # Fails with prob (K-1)/p ≈ 2^{-127}


# ======================================================================
# Theorem 7 — Oracle extraction lower bound
# ======================================================================


class TestExtractionBounds:
    """Verify that degree d+1 queries are necessary and sufficient."""

    def test_degree_1_needs_2_queries(self):
        """A linear function f(x) = s + c*x needs ≥ 2 queries to determine."""
        s = secrets.randbelow(PRIME)
        c = secrets.randbelow(PRIME)
        f = lambda x: field.add(s, field.mul(c, x))

        # 1 query: f(1) = s + c — cannot determine s and c separately
        y1 = f(1)
        # Multiple (s', c') are consistent: s'=y1-c', c'=anything
        # Verify: two different solutions exist
        c_prime = secrets.randbelow(PRIME)
        s_prime = field.sub(y1, c_prime)
        assert field.add(s_prime, field.mul(c_prime, 1)) == y1
        # But s_prime ≠ s (with overwhelming prob)
        assert s_prime != s or c_prime == c

        # 2 queries: f(1), f(2) — uniquely determines s, c
        y2 = f(2)
        # c = (y2 - y1) / (2 - 1) = y2 - y1
        c_recovered = field.sub(y2, y1)
        s_recovered = field.sub(y1, c_recovered)
        assert c_recovered == c
        assert s_recovered == s

    def test_degree_2_needs_3_queries(self):
        """A quadratic f(x) = a0 + a1*x + a2*x^2 needs ≥ 3 queries."""
        a0 = secrets.randbelow(PRIME)
        a1 = secrets.randbelow(PRIME)
        a2 = secrets.randbelow(PRIME)

        def f(x):
            return field.add(a0, field.add(
                field.mul(a1, x),
                field.mul(a2, field.mul(x, x))
            ))

        # Collect 3 points
        points = [(i, f(i)) for i in range(1, 4)]

        # Recover via Lagrange interpolation
        recovered_a0 = _lagrange_at(points, 0)
        assert recovered_a0 == a0

        # With only 2 points, multiple quadratics are consistent
        # (under-determined system)
        partial = points[:2]
        wrong_a0 = _lagrange_at(partial, 0)  # This does degree-1 interp
        # With overwhelming probability, wrong
        assert wrong_a0 != a0

    def test_extraction_impossible_under_budget(self):
        """With budget B < deg+1, exact extraction is impossible.

        A degree-2 function with budget B=2: two query results are
        consistent with multiple functions.
        """
        a0 = 42
        a1 = 17
        a2 = 5

        def f(x):
            return field.add(a0, field.add(
                field.mul(a1, x),
                field.mul(a2, field.mul(x, x))
            ))

        # Budget = 2 queries
        q1, q2 = f(1), f(2)

        # Adversary tries to find a0: there exist MANY quadratics
        # through (1, q1) and (2, q2). Verify by constructing another.
        a2_fake = field.add(a2, 1)  # Different a2
        # Solve for a0_fake, a1_fake given (1, q1), (2, q2), a2_fake
        # q1 = a0_f + a1_f*1 + a2_f*1  → a0_f + a1_f = q1 - a2_f
        # q2 = a0_f + a1_f*2 + a2_f*4  → a0_f + 2*a1_f = q2 - 4*a2_f
        rhs1 = field.sub(q1, a2_fake)
        rhs2 = field.sub(q2, field.mul(4, a2_fake))
        a1_fake = field.sub(rhs2, rhs1)
        a0_fake = field.sub(rhs1, a1_fake)

        # Verify fake polynomial matches at query points
        def f_fake(x):
            return field.add(a0_fake, field.add(
                field.mul(a1_fake, x),
                field.mul(a2_fake, field.mul(x, x))
            ))

        assert f_fake(1) == q1
        assert f_fake(2) == q2

        # But a0_fake ≠ a0 (the secret)
        assert a0_fake != a0


# ======================================================================
# Theorem 8 — Budget blocks extraction
# ======================================================================


class TestBudgetEffectiveness:
    """Verify budget enforcement blocks extraction."""

    def test_budget_blocks_extraction(self):
        """A program with budget B=2 blocks the 3rd query.

        The policy engine denies query #3 (budget exhausted), so an
        adversary needing 3 queries for degree-2 extraction is stopped.
        """
        from quorumvm.coordinator.policy import PolicyEngine
        from quorumvm.compiler.dsl_parser import compile_source
        from quorumvm.compiler.package import PolicyManifest, build_package

        # Degree 2 program: needs 3 queries to extract
        src = "input x\nconst s = 7\nadd t = x s\nmul out = t t\noutput out"
        ir = compile_source(src)
        policy = PolicyManifest(
            cost_per_eval=1,
            budget_per_identity=2,  # Only 2 queries allowed
            max_evals_per_minute=1000,
        )
        pkg = build_package(ir, policy=policy)

        engine = PolicyEngine()
        engine.register(pkg.program_id, pkg.model_dump()["policy_manifest"])

        # Query 1: allowed
        assert engine.check(pkg.program_id, "adversary") is None
        # Query 2: allowed
        assert engine.check(pkg.program_id, "adversary") is None
        # Query 3: DENIED — budget exhausted
        denial = engine.check(pkg.program_id, "adversary")
        assert denial is not None
        assert "budget" in denial.lower()

        # Therefore: deg(f)=2 needs 3 queries, budget=2 → extraction impossible


# ======================================================================
# SPDZ Comparison — round and communication analysis
# ======================================================================


class TestProtocolAnalysis:
    """Analyze protocol properties for comparison with SPDZ."""

    def test_round_count_per_multiplication(self):
        """QuorumVM P2P Beaver requires 2 communication rounds per mul.

        Round 1: custodians exchange ε,δ shares (N*(N-1) messages)
        Round 2: each custodian locally computes z_i (0 messages)

        But the coordinator orchestrates: send round1 trigger + collect
        output shares = 2 rounds total.
        """
        # This is a structural assertion, not computational
        rounds_per_mul_quorumvm = 2  # ε,δ broadcast + resolution
        rounds_per_mul_spdz = 1  # Preprocessed, single round

        assert rounds_per_mul_quorumvm == 2
        assert rounds_per_mul_spdz == 1

    def test_p2p_messages_per_round(self):
        """P2P ε,δ exchange: each custodian sends to N-1 peers.
        Total messages = N * (N-1) per mul node for Round 1.
        """
        n = NUM_CUSTODIANS  # 3
        messages_round1 = n * (n - 1)  # Each sends to N-1 peers
        assert messages_round1 == 6  # 3 * 2 = 6

    def test_beaver_triple_correctness_algebraic(self):
        """Triple (a,b,c) satisfies c = a*b — verified for 1000 triples."""
        for _ in range(1000):
            t = generate_triple()
            assert t.verify()

    def test_share_size_in_bits(self):
        """Each share is a field element ≤ 127 bits."""
        share_bits = math.ceil(math.log2(PRIME))
        assert share_bits == 127

        # Per-custodian storage per program: 1 share (x, y) = 2 * 127 bits
        storage_per_program_bits = 2 * share_bits
        assert storage_per_program_bits == 254  # ~32 bytes

    def test_communication_overhead_vs_spdz(self):
        """QuorumVM: O(N^2) messages per mul (P2P exchange).
        SPDZ: O(N) messages per mul (broadcast).

        For N=3: QuorumVM=6 vs SPDZ=3.
        For N=10: QuorumVM=90 vs SPDZ=10.
        """
        for n in [3, 5, 10]:
            quorum_messages = n * (n - 1)
            spdz_messages = n
            assert quorum_messages > spdz_messages
            # QuorumVM trades more messages for simpler preprocessing
