# PLAN-B: QuorumVM — Extraction-Resistant Computation via Threshold Execution (Foundational Draft)

**Status:** Publicly shareable *foundational* whitepaper (engineering-first, open research).  
**Purpose:** Define a practical architecture that *raises the cost of functional extraction* (including by future AGI) by ensuring no single machine ever holds full authority to execute or fully reconstruct the program.

---

## 0. Executive Summary

PLAN-B proposes **QuorumVM**, a *versioned* runtime where programs are executed through **K-of-N threshold participation** of independent custodians.  
The central idea is **not** “make code unreadable,” but:

> Make the capability to execute the official program require a quorum, and limit oracle access so black-box cloning becomes expensive and detectable.

This approach is compatible with established primitives (threshold cryptography, secret sharing, MPC-style evaluation) and pairs them with an “oracle control plane” that governs query budgets and auditing.

---

## 1. Motivation

As reverse engineering and automated program synthesis scale, “software as a static artifact” becomes increasingly extractable:

- binaries can be disassembled/decompiled,
- execution can be traced,
- behavior can be learned via repeated queries.

PLAN-B is a response to a future where extraction becomes cheap and largely automated. We focus on **raising extraction cost asymmetrically**.

---

## 2. Problem Statement

We want a system that provides:

1. **Resistance to functional extraction:** preventing an adversary from building a *generalizing* equivalent implementation without compromising a threshold of independent parties.
2. **Resistance to abuse:** preventing unauthorized or high-impact use, even if the adversary understands the system.
3. **Versioned evolution (B):** programs change over time; new versions must be activated under quorum control.

---

## 3. Threat Model (MVP)

### Adversary can:
- Obtain coordinator and custodian code/binaries.
- Compromise and fully control **t < K** custodians (root, memory, traffic).
- Submit oracle queries under system policies (rate limits, budgets).
- Use advanced automated analysis (including AGI-level capability).

### Out of scope (for MVP):
- **t ≥ K** compromise/collusion.
- Hardware side-channel resistance.
- Perfect prevention of black-box approximation under unlimited oracle access.

---

## 4. Core Security Invariants

1. **No single point of authority:** executing the official program requires **K-of-N**.
2. **No single point of knowledge:** secrets required for evaluation are **secret-shared**; no custodian holds them fully.
3. **Oracle access is governed:** budgets, rate limits, anomaly detection, immutable audit.
4. **Version activation is governed:** new versions require threshold approvals.
5. **Security degrades gracefully:** compromise impact scales with number of custodians compromised.

---

## 5. Foundational Architecture

### Components
- **DSL / IR (restricted):** circuit-like DAG (arith ops; optional conditionals).
- **Compiler:** DSL → IR → Program Package (versioned).
- **Custodians (N):** hold secret shares and evaluate IR on shares.
- **Coordinator:** orchestrates evaluation, enforces policy, reconstructs only with quorum.
- **Oracle Control Plane:** budgets, rate limiting, tickets, immutable logs.
- **Governance / Activation:** K-of-N approvals to activate a version.

---

## 6. “No Clone Without Quorum” Property (Informal)

Let version `v` define computation `f_v(x; S_v)`, where `S_v` are secret parameters distributed among custodians.

**Claim (informal, MVP):**  
With compromise of **t < K** custodians, an adversary cannot:
- reconstruct `S_v`, nor
- execute `f_v` for new inputs outside official policy,  
and cannot practically train an equivalent generalizing clone unless it obtains excessive oracle access (which is budgeted and logged).

This is not “absolute impossibility”; it is a *cost and access* argument anchored in threshold control + anti-oracle governance.

---

## 7. Concrete Example (Anchor Use Case)

### Proprietary Scoring Engine (Evolving Program)
A company has a scoring function whose value lies in secret parameters and decision logic, updated frequently:

- `score_v(x) = g_v(x; S_v)`

Risks:
- theft via RE of binaries/services,
- cloning via oracle queries.

PLAN-B:
- `S_v` is secret-shared across N custodians,
- evaluation requires K shares,
- version `v` becomes active only via K-of-N approvals,
- oracle access is budgeted and audited.

Outcome:
- stealing one server or one custodian is insufficient,
- cloning becomes either (a) a multi-party compromise problem, or (b) a detectable, costly query-extraction campaign.

---

## 8. Oracle Control Plane (Mandatory)

Without oracle controls, any “hidden” function can be approximated by enough I/O.

Minimum controls:
- **Identity-bound budgets** (cost units per eval)
- **Rate limiting** (token bucket; adaptive throttling)
- **Ticketing** (signed, expiring tickets per eval)
- **Immutable audit log** (append-only; chained hashes/HMAC)
- **Emergency degrade** (deny / restrict / require re-approval under suspicion)

---

## 9. Versioning & Governance (Program Changes Over Time)

### Activation
- A new Program Package `v` is proposed.
- Custodians verify package hash + policy manifest.
- Each custodian issues an approval signature.
- When approvals ≥ K, version becomes **ACTIVE**.

### Rotation (post-MVP)
- proactive resharing / periodic share rotation to reduce long-lived compromise impact
- custodian replacement procedures (revocation + reconstitution)

---

## 10. What PLAN-B is NOT

- Not obfuscation for evading audits.
- Not a malware-packing technique.
- Not a promise of absolute unbreakability under total compromise.
- Not a general-purpose distributed OS.

It is a *foundational pattern* for making extraction and misuse materially harder under realistic constraints.

---

## 11. MVP Success Criteria

The MVP is successful if it demonstrates:

1. **Threshold execution:** fewer than K custodians cannot reconstruct secrets or evaluate for new inputs.
2. **Version governance:** activation requires K approvals.
3. **Anti-oracle controls:** budgets and rate limits are enforced; all evals are auditable.
4. **Developer workflow:** compile → activate → evaluate → observe policy effects.

---

## 12. Roadmap

### Phase I (MVP)
- Restricted DSL
- Shamir (K-of-N) or additive (then upgrade)
- Coordinator + N custodians via Docker Compose
- Activation approvals
- Budgets + rate limiting + audit log
- Demo script + tests

### Phase II (Hardening)
- proactive resharing (rotation)
- stronger anomaly detection
- custodian heterogeneity + governance policies

### Phase III (Research)
- formalization of oracle-limited extraction
- bounds/tradeoffs: DSL expressiveness vs extractability vs cost
- threat models including partial collusion over time

---

## 13. Open Participation

PLAN-B is compatible with an open research model:
- publish the architecture and MVP openly,
- treat hard questions (oracle extraction, bounds) as research tracks,
- accept that real security comes from transparent threat modeling, not secrecy.

