# PLAN-B QuorumVM — Roadmap de Validación Whitepaper

**Objetivo:** Construir una test suite que demuestre *cada invariante de seguridad* del whitepaper (§4, §6, §8, §11) de forma automatizada y reproducible.

---

## MVP Success Criteria (Whitepaper §11)

| # | Criterio | Test | Estado |
|---|---|---|---|
| 1 | **Threshold execution:** < K custodians no pueden reconstruir secretos ni evaluar | `TestThresholdApprovals`, `TestThresholdSecretSharing` | ✅ Pasa |
| 2 | **Version governance:** activación requiere K approvals; < K no activa | `TestThresholdApprovals`, `TestEvalRequiresActive` | ✅ Pasa |
| 3 | **Anti-oracle controls:** budgets + rate limits + audit chain | `TestBudgetEnforcement`, `TestRateLimitEnforcement`, `TestAuditChainIntegrity` | ✅ Pasa |
| 4 | **Developer workflow:** compile → activate → evaluate → observe | `TestFullWhitepaperFlow` | ✅ Pasa |

## Core Security Invariants (Whitepaper §4)

| # | Invariante | Test | Estado |
|---|---|---|---|
| 4.1 | No single point of authority (K-of-N para ejecutar) | `test_fewer_than_k_approvals_stays_pending`, `test_invalid_signature_rejected` | ✅ Pasa |
| 4.2 | No single point of knowledge (shares insuficientes no reconstruyen) | `test_fewer_than_k_shares_do_not_reconstruct`, `test_fewer_than_k_output_shares_wrong_result_e2e` | ✅ Pasa |
| 4.3 | Oracle access is governed (budgets, rate limits, audit) | `test_budget_via_coordinator_endpoint`, `test_rate_limit_via_coordinator_endpoint` | ✅ Pasa |
| 4.4 | Version activation is governed (K approvals) | `test_exactly_k_approvals_activates`, `test_eval_rejected_when_pending` | ✅ Pasa |
| 4.5 | Security degrades gracefully (1 custodian caído, quorum opera) | `test_one_custodian_down_quorum_still_works`, `test_too_many_custodians_down_fails` | ✅ Pasa |

## Anti-Oracle (Whitepaper §8)

| Control | Test | Estado |
|---|---|---|
| Identity-bound budgets | `test_budget_allows_then_denies`, `test_budget_per_identity_isolation`, `test_budget_via_coordinator_endpoint` | ✅ Pasa |
| Rate limiting (token bucket) | `test_rate_limit_unit`, `test_rate_limit_refills_over_time`, `test_rate_limit_via_coordinator_endpoint` | ✅ Pasa |
| Immutable audit log (hash-chain) | `test_audit_chain_valid_after_full_flow`, `test_audit_records_eval_events`, `test_audit_entries_are_hash_chained` | ✅ Pasa |

---

## Progreso

- [x] Crear `tests/test_whitepaper_compliance.py` (20 tests)
- [x] Test: < K approvals no activan programa
- [x] Test: eval rechazado cuando programa en estado PENDING
- [x] Test: < K shares no reconstruyen output correcto (E2E)
- [x] Test: rate-limit enforcement automatizado con asserts
- [x] Test: graceful degradation — 1 custodian caído, quorum aún funciona
- [x] Test: flujo E2E completo del whitepaper (compile → activate → eval → verify → budget → audit)
- [x] Todos los tests pasan ✅ (71/71 — 51 originales + 20 whitepaper)
- [x] Rebuild imagen Docker + re-deploy a GKE
- [x] Verificar tests en cluster ✅ (13/13 distributed tests passed)

---

## Test Results Summary

```
tests/test_whitepaper_compliance.py  20 passed   ← NUEVO
tests/test_e2e.py                     5 passed
tests/test_compiler.py               11 passed
tests/test_field.py                  10 passed
tests/test_shamir.py                  7 passed
tests/test_package.py                 5 passed
tests/test_executor.py                4 passed
tests/test_policy.py                  3 passed
tests/test_audit.py                   3 passed
tests/test_signatures.py              3 passed
─────────────────────────────────────────────────
TOTAL                                71 passed ✅
```

## Distributed Cluster Test Results (GKE)

Ran as K8s Job `quorumvm-whitepaper-tests` against live services in namespace `quorumvm`
on cluster `dbtoagent-cluster` (GKE, `car-dealer-ai-472618`).

```
Coordinator: http://coordinator.quorumvm.svc.cluster.local:8000
Custodians:  custodian-{0,1,2}.quorumvm.svc.cluster.local:{9100,9101,9102}
K=2, N=3

§4.1  ✅ fewer_than_k_approvals_stays_pending
      ✅ invalid_signature_rejected
      ✅ eval_rejected_when_pending
§4.2  ✅ k_shares_reconstruct_secret
      ✅ fewer_than_k_shares_fail
§4.4  ✅ exactly_k_approvals_activates
§4.5  ✅ eval_succeeds_with_one_custodian_slow
§8    ✅ budget_allows_then_denies
      ✅ budget_per_identity_isolation
      ✅ rate_limit_denies_burst
      ✅ audit_chain_integrity
      ✅ audit_records_eval_ok_and_denied
§11   ✅ full_e2e_compile_activate_eval_budget_audit

RESULTS: 13/13 passed
ALL WHITEPAPER INVARIANTS VERIFIED ✅
```

*Última actualización: 2026-02-16 — distributed cluster tests COMPLETE*
