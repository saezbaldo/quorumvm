# PLAN-B: Codex Build Instructions — QuorumVM MVP (Engineering-First)

You are Codex. Implement the MVP described in PLAN-B (QuorumVM).  
Goal: a runnable, testable prototype of threshold execution over a restricted DSL with version activation and anti-oracle controls.

---

## 1) Non-negotiables
- Must run locally via **Docker Compose**.
- Must include automated tests (pytest or equivalent).
- Must include a demo script:
  1) compile DSL program → Program Package
  2) activate version with K approvals
  3) evaluate inputs until budgets/rate limits trigger
- Keep DSL restricted (circuit/DAG). **No general code execution**. **No filesystem/network I/O** from programs.

---

## 2) Recommended stack
- Python 3.11+
- FastAPI
- Pydantic
- pytest
- Optional Redis (can start in-memory)

Repo should be simple and readable.

---

## 3) Repo layout (suggested)
- /compiler
  - dsl_parser.py
  - ir.py
  - package.py
- /crypto
  - field.py
  - shamir.py
  - signatures.py (MVP: HMAC per custodian is ok)
- /coordinator
  - app.py
  - policy.py
  - audit.py
- /custodian
  - app.py
  - executor.py
- /demo
  - run_demo.py
- docker-compose.yml
- README.md

---

## 4) DSL (MVP)
A tiny declarative DSL that compiles to a DAG.

Example:
input x
const c = 7
add t = x c
mul y = t t
output y

Rules:
- No loops, no recursion
- Every identifier is a wire
- Ops: add/sub/mul (over prime field)
- Inputs and consts feed ops
- Single output for MVP

Compiler outputs JSON IR:
- nodes: {id, type, op, inputs, value}
- output_node_id

---

## 5) Finite field arithmetic
Implement prime field F_p with a fixed prime p (hardcode in config).
Provide add/sub/mul and reduce mod p.

---

## 6) Secret sharing (K-of-N)
Implement **Shamir secret sharing** (preferred):
- share(secret, n, k): random polynomial deg k-1; output points (i, f(i))
- reconstruct(points_subset): Lagrange at x=0

If Shamir is too heavy for v0, you may implement additive shares but then K must equal N. Shamir is strongly preferred.

---

## 7) Program Package (versioned)
A JSON artifact containing:
- program_id = SHA256(ir_json + policy_manifest_json + secret_manifest_json)
- version string
- ir
- secret_manifest:
  - for MVP: one secret parameter S_v (field element)
- policy_manifest:
  - cost_per_eval
  - budget_per_identity
  - max_evals_per_minute

---

## 8) Activation workflow (K approvals)
Custodian API:
- POST /approve { program_id } -> { custodian_id, signature }
- POST /install { program_package, share_of_S_v } -> ok

Coordinator:
- stores approvals
- when approvals >= K for program_id, marks ACTIVE

Signatures for MVP can be HMAC(custodian_key, program_id). Keep it simple but consistent.

---

## 9) Evaluation workflow
Coordinator API:
- POST /eval { identity_id, program_id, inputs: {x: int} }

Coordinator steps:
1) Enforce policy:
   - rate limit by identity
   - budget by identity (cost units)
2) Split each input into N shares (Shamir share with same k)
3) Send each custodian:
   - POST /eval_share { program_id, input_shares, request_id }
4) Collect output shares from custodians
5) When >= K shares returned, reconstruct output
6) Append audit entry (chained log)
7) Return output

Custodian API:
- POST /eval_share { program_id, input_shares, request_id } -> { output_share }

Custodian executor:
- Evaluate IR on shares:
  - Input nodes: use provided share
  - Const nodes: represent constant as shares (Shamir share constant with same k)
  - Ops: add/sub/mul performed on shares in field
  - Output: return share of output wire

---

## 10) Oracle control plane (anti-extraction)
Implement at least:
- budget_per_identity (in-memory dict ok for MVP)
- max_evals_per_minute (token bucket)
- cost_per_eval deducted per successful eval
- immutable audit log:
  - JSON lines with (prev_hash, entry_hash) chain or HMAC chain

Demo must show budget exhaustion and rate limiting.

---

## 11) Demo script
`python demo/run_demo.py` should:
- compile a sample program
- generate secret S_v and Shamir shares for custodians
- install package + shares onto custodians
- collect approvals (>=K)
- activate program
- run evaluations:
  - print outputs
  - intentionally exceed budgets/rate limits to show enforcement

---

## 12) Tests
Include tests for:
- field ops
- Shamir share/reconstruct
- DSL compiler
- end-to-end:
  - bring up services
  - install + activate
  - evaluate and verify deterministic output

---

## 13) Success criteria
- `docker compose up --build` works
- demo runs end-to-end
- fewer than K shares cannot reconstruct secret/output (documented + tested)
- policy enforcement is visible and logged

---

## Guardrails
- Do NOT implement code obfuscation techniques.
- Do NOT add general code execution or unsafe tool access.
- Keep it deterministic, auditable, and minimal.
