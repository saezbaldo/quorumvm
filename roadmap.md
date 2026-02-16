# QuorumVM — Roadmap

Last updated: **2025-07-15**

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

---

## 🔧 In Progress

### Phase 7 — GKE Redeploy with Beaver + Pool
- [ ] Rebuild Docker image with Beaver + pool code
- [ ] Push to GCR and rolling-update K8s deployments
- [ ] Re-run 13 distributed cluster tests → all pass
- [ ] Update `test_whitepaper_cluster.py` to test Beaver flow on cluster

---

## 📋 Planned

### Phase 8 — Coordinator Visibility Reduction
**Problem**: Coordinator currently sees reconstructed (ε, δ) during Beaver rounds. While these are masked and reveal nothing about raw inputs, a malicious coordinator could attempt offline attacks.

- [ ] Research: peer-to-peer custodian communication for masked-diff exchange
- [ ] Research: threshold reconstruction without coordinator (custodian-to-custodian shares)
- [ ] Evaluate trade-offs: latency, complexity, trust model

### Phase 9 — DSL Expansion
- [ ] Constants in DSL (`const seven = 7`)
- [ ] Multi-output programs (return multiple values)
- [ ] Conditional-like patterns via MUX gates: `mux(selector, a, b)`
- [ ] Standard library of common functions (dot product, polynomial eval)
- [ ] Compiler optimizations: common subexpression elimination, dead node pruning

### Phase 10 — Proactive Resharing & Custodian Rotation
- [ ] Custodian onboarding: generate new shares without reconstructing the secret
- [ ] Custodian retirement: remove a custodian while maintaining threshold
- [ ] Periodic resharing to limit window of compromise
- [ ] Protocol tests for resharing correctness

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
| Total tests | 108 passing |
| Local unit/integration | 95 |
| Beaver protocol tests | 20 |
| Beaver pool tests | 5 |
| Whitepaper compliance (local) | 20 |
| Distributed cluster (GKE) | 13 |
| GitHub commits | 3 (pending push) |
| Open phases | 5 (Phase 7–11) |
