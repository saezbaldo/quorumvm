# QuorumVM — Roadmap

Last updated: **2026-02-18**

---

## ✅ Completed

### Phase 1 — MVP Core
- [x] Prime-field arithmetic (`F_p`, p = 2¹²⁷−1)
- [x] Shamir K-of-N secret sharing
- [x] HMAC-SHA256 per-custodian signatures
- [x] DSL compiler → DAG IR → versioned Program Package (SHA-256)
- [x] Coordinator: policy engine (budget + rate-limit), hash-chained audit log
- [x] Custodian: DAG executor, install/approve/eval endpoints
- [x] End-to-end demo: `f(x)=(x+7)²`
- [x] 51 unit + integration tests

### Phase 2 — GKE Deployment
- [x] Dockerfile & docker-compose.yml
- [x] Kubernetes manifests (namespace, 3 custodians, coordinator)
- [x] Docker image pushed to GCR
- [x] 4 pods running on `dbtoagent-cluster` (us-central1)
- [x] Demo Job executed successfully inside cluster

### Phase 3 — Whitepaper Compliance
- [x] 20 local compliance tests mapping to whitepaper §4.1, §4.2, §4.4, §4.5, §8, §11
- [x] 13 distributed cluster tests against live GKE services (real HTTP, no mocks)
- [x] All 84 tests (51 + 20 + 13) passing

### Phase 4 — GitHub & Documentation
- [x] Public repo: [saezbaldo/quorumvm](https://github.com/saezbaldo/quorumvm)
- [x] Comprehensive English README with architecture, API reference, test results

### Phase 5 — Beaver Triple Protocol
- [x] `crypto/beaver.py` — Triple generation, Shamir sharing, round primitives, coordinator finalize
- [x] `custodian/executor.py` — `StepExecutor` with pause/resume at `mul` nodes
- [x] `custodian/app.py` — New endpoints: `/install_beaver`, `/eval_beaver`, `/beaver_round2`
- [x] `coordinator/app.py` — Full Beaver orchestration: Shamir-share inputs, 2-round interactive protocol, ε·δ correction
- [x] 18 Beaver tests (generation, sharing, protocol correctness, StepExecutor, E2E HTTP)
- [x] README updated to reflect Beaver architecture

### Phase 6 — Beaver Triple Pool
- [x] `generate_triples_for_program()` accepts `pool_size` parameter
- [x] Custodians store FIFO pool per mul node; one triple consumed per eval
- [x] Pool exhaustion → HTTP 409 with clear error message
- [x] `POST /replenish_beaver` endpoint to add fresh triples
- [x] `GET /beaver_pool/{program_id}` endpoint to check remaining capacity
- [x] `DEFAULT_BEAVER_POOL_SIZE = 5` in config.py
- [x] 5 pool-specific tests: multiple evals, exhaustion, replenishment, status, distinct triples
- [x] Demo script updated with Beaver pool flow
- [x] All 108 tests passing (95 local + 13 cluster)

### Phase 7 — GKE Redeploy with Beaver + Pool
- [x] Docker image rebuilt with Beaver + pool code (tags: `latest`, `v3-beaver-pool`)
- [x] Pushed to GCR (`gcr.io/car-dealer-ai-472618/quorumvm`)
- [x] Rolling-update of all 4 K8s deployments (coordinator + 3 custodians)
- [x] Re-ran 13 distributed cluster tests → **13/13 passed ✅**
- [x] All whitepaper invariants verified on live GKE cluster

---

##  Planned

### Phase 8 — Coordinator Visibility Reduction (P2P Beaver)
- [x] Peer-to-peer ε,δ share exchange between custodians (`POST /beaver_shares`)
- [x] Local reconstruction: each custodian reconstructs ε,δ via Lagrange (`POST /beaver_resolve_p2p`)
- [x] ε*δ correction folded into all custodian shares (Σ L_i(0)=1 property)
- [x] Coordinator no longer reconstructs ε or δ — zero visibility
- [x] `coordinator_finalize()` no longer called in production flow (kept for backward compat)
- [x] `_beaver_epsilons` state dict removed from coordinator
- [x] `custodian_mul_round2_with_correction()` added to `crypto/beaver.py`
- [x] Audit log records `mode: "beaver_p2p"` for P2P evaluations
- [x] 2 new Phase 8 tests: `test_coordinator_never_sees_epsilon_delta`, `test_p2p_round2_with_correction_no_finalize`
- [x] Graceful degradation works with P2P (K=2 of N=3 custodians)
- [x] All 110 tests passing (97 local + 13 cluster)
- [x] Docker image `v4-p2p-beaver` deployed, 13/13 distributed tests pass

### Phase 9 — DSL Expansion
- [x] `neg` gate — unary additive inverse
- [x] `mux` gate — selector-based conditional: `mux(s, a, b) = s*a + (1-s)*b`
- [x] Multi-output programs — `output a b` or multiple `output` statements
- [x] IR updated: `output_node_ids` list + backward-compatible `output_node_id`
- [x] Stdlib macro: `dot <name> = <a1> <b1> ... <aN> <bN>` — dot product
- [x] Stdlib macro: `polyeval <name> = <x> <c0> <c1> ... <cN>` — Horner polynomial evaluation
- [x] Compiler optimizer: Common Subexpression Elimination (CSE)
- [x] Compiler optimizer: Dead Node Pruning
- [x] `compiler/optimizer.py` — `optimize()`, `eliminate_common_subexpressions()`, `prune_dead_nodes()`
- [x] Executor updated: `neg`, `mux`, `evaluate_ir_multi()`, `StepExecutor.outputs()`
- [x] Coordinator & custodian: multi-output support in legacy + Beaver + P2P paths
- [x] 25 new Phase 9 tests: gate types, multi-output, stdlib, CSE, dead-node pruning
- [x] All 122 tests passing (109 local + 13 cluster)

---

## 📋 Planned

### Phase 10 — Proactive Resharing & Custodian Rotation
- [x] `crypto/resharing.py` — zero-share polynomial generation, sub-share distribution, apply
- [x] `reshare()` — full proactive resharing round preserving the secret without reconstruction
- [x] `rotate_custodians()` — transfer shares to new custodian set via Lagrange interpolation
- [x] `_lagrange_at()` — Lagrange interpolation at arbitrary x (not just x=0)
- [x] Custodian endpoints: `/reshare_generate`, `/reshare_apply`, `/reshare_set_share`, `/reshare_lagrange_partial`, `/reshare_retire`
- [x] Coordinator endpoints: `POST /reshare` (orchestrated resharing), `POST /rotate` (full rotation with onboard/retire)
- [x] 31 Phase 10 tests: zero-share poly, sub-shares, reshare preserves secret, multi-round resharing, rotation (expand, shrink, replace), Lagrange interpolation, HTTP endpoint integration
- [x] All 166 tests passing (153 local + 13 cluster)
- [x] Docker image `v6-resharing` deployed to GKE, 13/13 distributed tests pass

### Phase 11 — Formal Security Analysis
- [ ] Formal model: define adversary capabilities, simulation-based security proof sketch
- [ ] Information-theoretic leakage analysis of ε, δ exposure
- [ ] Oracle-limited extraction: formalize budget bounds per §8
- [ ] Comparison with SPDZ/Overdrive in terms of rounds, communication, and trust

---

## 🔭 Future / Research

- **Comparison operators on shares** — evaluate `x > threshold` without revealing x (garbled circuits or comparison protocols)
- **SPDZ-style MAC authentication** — add information-theoretic MACs for active-security against malicious custodians
- **Hardware enclaves** — optional SGX/TDX for custodian execution to resist memory-dump attacks
- **Pre-processing phase separation** — offline triple generation vs. online evaluation for latency optimization
- **Federated custodian deployment** — custodians operated by different organizations across jurisdictions
- **Neural network inference** — evaluate simple feed-forward networks via arithmetic circuit compilation (ReLU approximation via polynomials)

---

## Progress Metrics

| Metric | Value |
|---|---|
| Total tests | 166 passing |
| Local unit/integration | 153 |
| Resharing & rotation tests | 31 |
| Beaver protocol tests | 22 |
| Beaver pool tests | 5 |
| Compiler tests | 26 |
| Executor tests | 14 |
| Whitepaper compliance (local) | 20 |
| Distributed cluster (GKE) | 13 |
| GitHub commits | 7 |
| Open phases | 1 (Phase 11) |
