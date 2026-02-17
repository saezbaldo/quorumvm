# QuorumVM — Formal Security Analysis

**Phase 11 — Security proofs, leakage analysis, extraction bounds, and protocol comparison.**

---

## 1. System Model and Notation

### 1.1 Participants

| Symbol | Description |
|---|---|
| $\mathcal{C} = \{C_1, \ldots, C_N\}$ | Set of $N$ custodians |
| $\mathcal{K}$ | Coordinator (orchestrator, no secret knowledge) |
| $\mathcal{A}$ | Adversary |
| $K$ | Threshold (minimum shares to reconstruct) |
| $\mathbb{F}_p$ | Prime field, $p = 2^{127} - 1$ (Mersenne prime M127) |

### 1.2 Secrets and Shares

A program $v$ has secret parameters $S_v \in \mathbb{F}_p$. The secret is Shamir-shared:

$$S_v = f(0), \quad f(x) = S_v + \sum_{j=1}^{K-1} a_j x^j, \quad a_j \stackrel{\$}{\leftarrow} \mathbb{F}_p$$

Each custodian $C_i$ holds share $(x_i, y_i)$ where $y_i = f(x_i)$.

### 1.3 Computation Model

The DSL compiles to a DAG of arithmetic gates over $\mathbb{F}_p$:
- **add/sub/neg**: linear operations (free on shares)
- **mul**: requires Beaver triple protocol (interactive, 2 rounds)
- **mux**: $\text{mux}(s, a, b) = s \cdot a + (1-s) \cdot b$ (2 multiplications)

A program $f_v(x; S_v)$ with $m$ multiplications requires $m$ Beaver triples.

---

## 2. Adversary Model

### 2.1 Capabilities

The adversary $\mathcal{A}$ can:

1. **Compromise** up to $t < K$ custodians (full memory/traffic access).
2. **Observe** all public communication (coordinator ↔ custodian HTTP traffic).
3. **Query** the system as an oracle, subject to policy constraints:
   - Budget: at most $B$ evaluations per identity.
   - Rate limit: at most $r$ evaluations per time window $\Delta t$.
4. **Analyze** all code, binaries, and protocol specifications (Kerckhoffs' principle).
5. **Use** unbounded computation (information-theoretic security model for secret sharing; computational model for oracle extraction).

### 2.2 Adversary Goals

| Goal | Formal Definition |
|---|---|
| **Secret Recovery** | Recover $S_v = f(0)$ from observed data |
| **Unauthorized Execution** | Compute $f_v(x^*; S_v)$ for a new input $x^*$ without quorum participation |
| **Functional Extraction** | Construct $\hat{f}$ such that $\Pr[\hat{f}(x) = f_v(x; S_v)] \geq 1 - \delta$ for $x \sim \mathcal{D}$ |

---

## 3. Security Theorems

### Theorem 1 — Threshold Secret Sharing Security (Information-Theoretic)

**Statement.** Let $S_v$ be shared via Shamir's $(K, N)$ scheme over $\mathbb{F}_p$. An adversary who obtains any $t < K$ shares learns zero information about $S_v$.

**Proof sketch.** For any $t < K$ shares $\{(x_{i_1}, y_{i_1}), \ldots, (x_{i_t}, y_{i_t})\}$ and any candidate secret $s^* \in \mathbb{F}_p$, there exists exactly one polynomial of degree $\leq K-1$ passing through the $t$ given points with $f(0) = s^*$. Therefore:

$$H(S_v \mid \text{any } t < K \text{ shares}) = H(S_v)$$

This is **information-theoretic**: it holds against computationally unbounded adversaries. $\square$

**Verified by:** `test_threshold_info_theoretic` — for every possible secret value, verifies that $t < K$ shares are consistent.

### Theorem 2 — Beaver Protocol Correctness

**Statement.** The Beaver multiplication protocol computes $z = x \cdot y$ correctly on shares.

**Proof.** Given Beaver triple $(a, b, c)$ with $c = a \cdot b$, let $\varepsilon = x - a$ and $\delta = y - b$. Each custodian $i$ computes:

$$z_i = c_i + \varepsilon \cdot b_i + \delta \cdot a_i + \varepsilon \cdot \delta$$

Reconstruction yields:

$$z = \sum_i L_i(0) \cdot z_i = c + \varepsilon b + \delta a + \varepsilon \delta$$
$$= ab + (x-a)b + (y-b)a + (x-a)(y-b)$$
$$= ab + xb - ab + ya - ba + xy - xb - ya + ab$$
$$= xy \quad \square$$

**Verified by:** `test_beaver_algebraic_correctness` — symbolic verification over random field elements.

### Theorem 3 — Beaver ε,δ Leakage Analysis

**Statement.** The values $\varepsilon = x - a$ and $\delta = y - b$ are statistically independent of $x$ and $y$ individually.

**Proof.** Since $a \stackrel{\$}{\leftarrow} \mathbb{F}_p$ uniformly at random (independent of $x$), the distribution of $\varepsilon = x - a \pmod{p}$ is uniform over $\mathbb{F}_p$ regardless of $x$. Similarly for $\delta$.

However, the **pair** $(\varepsilon, \delta)$ together with the program structure reveals:

$$x = a + \varepsilon, \quad y = b + \delta$$

Therefore, **if** an adversary knows both:
- $(\varepsilon, \delta)$ from the protocol execution, **and**
- $(a, b)$ from compromising a custodian's Beaver shares

then $x$ and $y$ are fully revealed. But this requires $t \geq K$ (to reconstruct $a$ and $b$ from their Shamir shares).

**Information leaked by ε,δ alone:** Each $\varepsilon$ value is a uniform random element of $\mathbb{F}_p$. An adversary observing $Q$ evaluations sees $Q$ independent uniform values — mutual information $I(x; \varepsilon) = 0$.

**Verified by:** `test_epsilon_delta_uniform_distribution` — statistical test showing ε,δ are uniformly distributed.

### Theorem 4 — P2P Beaver: Coordinator Zero-Knowledge

**Statement.** In the P2P Beaver flow (Phase 8+), the coordinator never observes $\varepsilon$, $\delta$, or any share values.

**Proof.** In the P2P flow:
1. Custodians exchange ε,δ **shares** directly with each other (peer-to-peer).
2. Each custodian locally reconstructs ε,δ from the received shares.
3. Each custodian computes $z_i = c_i + \varepsilon b_i + \delta a_i + \varepsilon\delta$ locally.
4. The coordinator only receives **output shares** $z_i$ (which are uniformly random individually).

The coordinator's view: $\{z_1, \ldots, z_N\}$ (random field elements) + the final reconstructed output. The intermediate values $\varepsilon, \delta, x_i, y_i, a_i, b_i, c_i$ are never transmitted to or through the coordinator. $\square$

**Verified by:** `test_coordinator_zero_knowledge_view`

### Theorem 5 — Proactive Resharing Correctness

**Statement.** After a resharing round, the new shares reconstruct to the same secret $S_v$.

**Proof.** Each custodian $i$ generates $g_i(x)$ of degree $K-1$ with $g_i(0) = 0$. New shares:

$$y'_j = y_j + \sum_{i=1}^{N} g_i(x_j) = f(x_j) + \underbrace{\sum_{i=1}^{N} g_i(x_j)}_{h(x_j)}$$

where $h(x) = \sum_i g_i(x)$ is a polynomial of degree $K-1$ with:

$$h(0) = \sum_{i=1}^{N} g_i(0) = 0$$

Therefore $f'(x) = f(x) + h(x)$ is a degree $K-1$ polynomial with $f'(0) = f(0) + 0 = S_v$. $\square$

**Verified by:** `test_resharing_preserves_secret_formal`

### Theorem 6 — Resharing Forward Security

**Statement.** Old shares from before a resharing round are incompatible with new shares from after.

**Proof.** The old polynomial is $f(x)$ and the new polynomial is $f'(x) = f(x) + h(x)$ where $h \neq 0$ (with overwhelming probability since $h$ has random non-zero coefficients). For $x_j \neq 0$:

$$\Pr[f(x_j) = f'(x_j)] = \Pr[h(x_j) = 0] \leq \frac{K-1}{p}$$

which is negligible for $p = 2^{127} - 1$. An adversary holding $t_{\text{old}}$ old shares and $t_{\text{new}}$ new shares (with $t_{\text{old}} + t_{\text{new}} < K$ each) cannot combine them: they lie on **different** polynomials. $\square$

**Verified by:** `test_resharing_forward_security`

---

## 4. Oracle-Limited Extraction Bounds

### 4.1 Setup

The adversary queries the system as a black-box oracle $\mathcal{O}: \mathbb{F}_p^d \to \mathbb{F}_p$ where $d$ is the number of inputs.

The program $f_v$ is an arithmetic circuit of depth $D$ and degree $\deg(f_v)$ over $\mathbb{F}_p$, parameterized by secret $S_v$.

### 4.2 Exact Extraction

**Theorem 7.** To exactly recover $f_v$ (up to the secret parameters), an adversary with oracle access needs:

$$Q_{\text{exact}} \geq \deg(f_v) + 1$$

queries (from the Schwartz-Zippel lemma applied in reverse: a polynomial of degree $d$ is determined by $d+1$ evaluations).

For the QuorumVM DSL:
- A program with $m$ multiplications has degree $\leq 2^m$ (worst case, nested multiplications).
- A linear program (no multiplications) has degree 1 → needs $\geq 2$ queries.
- A program `f(x) = (x+s)^2` has degree 2 → needs $\geq 3$ queries.

**With budget $B$ evaluations:** If $B < \deg(f_v) + 1$, exact extraction is **information-theoretically impossible** (there are multiple polynomials consistent with $B$ evaluations).

**Verified by:** `test_extraction_bound_exact`

### 4.3 Approximate Extraction (PAC Learning)

For approximate extraction (learning $\hat{f}$ with error $\leq \delta$ on fraction $\geq 1-\epsilon$ of inputs):

By PAC learning theory for polynomial concept classes, the sample complexity is:

$$Q_{\text{approx}} = \Omega\left(\frac{\deg(f_v) + \log(1/\delta)}{\epsilon}\right)$$

For a degree-$d$ polynomial over $\mathbb{F}_p$:
- Even with $d = 2$ and $\epsilon = 0.01$, $\delta = 0.01$: need $Q \geq 600+$ queries.
- Budget $B \ll Q_{\text{approx}}$ makes approximate extraction infeasible.

### 4.4 Budget Effectiveness

**Theorem 8.** The oracle control plane limits extraction as follows:

Let the program have degree $d$. With identity budget $B$ and rate limit $r$ per window $\Delta t$:

1. **Extraction is impossible** if $B < d + 1$ (exact) or $B < Q_{\text{approx}}$ (approximate).
2. **Extraction takes time** $\geq B / r \cdot \Delta t$ even if budget suffices.
3. **Extraction is detectable:** the audit log records every query; anomaly detection can trigger emergency throttling.

The **cost of extraction** $C_{\text{extract}}$ combines:

$$C_{\text{extract}} = C_{\text{query}} \cdot Q + C_{\text{time}} \cdot T_{\text{min}} + C_{\text{stealth}}$$

where $C_{\text{stealth}}$ is the cost of avoiding detection across $Q$ queries.

**Verified by:** `test_budget_blocks_extraction`

---

## 5. Comparison with SPDZ/Overdrive

| Property | QuorumVM | SPDZ | Overdrive |
|---|---|---|---|
| **Secret sharing** | Shamir $(K, N)$ | Additive (N-of-N) + MAC | Shamir $(K, N)$ + MAC |
| **Adversary model** | Honest-but-curious ($t < K$) | Active (malicious) | Active (malicious) |
| **MAC authentication** | None (MVP) | Information-theoretic MAC $\alpha$ | Information-theoretic MAC $\alpha$ |
| **Online rounds per mul** | 2 (ε,δ broadcast + compute) | 1 (preprocessed) | 1 (preprocessed) |
| **Preprocessing** | Coordinator generates triples | Offline phase (Somewhat HE or OT) | Offline phase (Overdrive LowGear/HighGear) |
| **Triple generation** | Trusted dealer (coordinator) | Distributed (no dealer) | Distributed (no dealer) |
| **Communication per mul** | $O(N^2)$ (P2P ε,δ exchange) | $O(N)$ (broadcast) | $O(N)$ (broadcast) |
| **Proactive resharing** | ✅ Implemented | Not standard | Not standard |
| **Oracle control plane** | ✅ Budget + rate limit + audit | Not included | Not included |
| **Cheating detection** | Via audit log (post-hoc) | Immediate (MAC check) | Immediate (MAC check) |

### 5.1 Rounds Comparison

For a circuit with $m$ multiplications, $d$ depth:

| | QuorumVM (P2P) | SPDZ |
|---|---|---|
| Online rounds | $2m$ (sequential muls) or $2d$ (parallel) | $d$ (parallel muls) |
| Messages per round | $N(N-1)$ P2P shares | $N$ broadcasts |
| Preprocessing | 1 round (trusted dealer) | $O(m)$ offline rounds |

QuorumVM trades **1 extra round per mul** (for ε,δ distribution) against **simpler preprocessing** (trusted coordinator vs. distributed HE-based triple generation).

### 5.2 Trust Comparison

| | QuorumVM | SPDZ/Overdrive |
|---|---|---|
| **Trusted dealer?** | Yes (coordinator generates triples) | No (distributed generation) |
| **Active security?** | No (honest-but-curious) | Yes (MAC-enforced) |
| **Post-compromise detection?** | Yes (audit log) | Yes (immediate abort) |

**Key tradeoff:** QuorumVM's trusted dealer simplifies the system at the cost of requiring trust in the coordinator during preprocessing. SPDZ eliminates this trust requirement but at significantly higher computational cost (homomorphic encryption or oblivious transfer for triple generation).

### 5.3 When QuorumVM is Preferable

1. **Controlled deployment**: custodians operated by the same organization → honest-but-curious is realistic.
2. **Oracle protection matters**: budgets/rate limits are essential → SPDZ doesn't address this.
3. **Simpler operations**: few multiplications → round overhead is minimal.
4. **Custodian rotation needed**: proactive resharing is built-in.

### 5.4 When SPDZ/Overdrive is Preferable

1. **Multi-party computation**: custodians operated by mutually distrusting parties → need active security.
2. **High-throughput**: many multiplications, amortized preprocessing.
3. **Malicious adversary**: need immediate abort on cheating.

---

## 6. Security Boundaries and Honest Limitations

### 6.1 What QuorumVM Does NOT Protect Against

1. **$t \geq K$ compromise**: if $K$ or more custodians are compromised, all secrets are recoverable.
2. **Malicious coordinator**: the coordinator sees the final reconstructed output. A malicious coordinator can:
   - Return wrong results (integrity violation, detectable via redundant evaluation).
   - Log and exfiltrate outputs (privacy violation for the *result*, not the *parameters*).
3. **Unlimited oracle access**: with enough queries ($Q \geq \deg(f_v) + 1$), any function is extractable regardless of threshold protection.
4. **Side channels**: timing, power analysis, memory access patterns are out of scope.
5. **Malicious custodians**: a malicious custodian can return incorrect shares (no MAC verification in MVP). This causes incorrect results, not secret leakage.

### 6.2 Residual Risks

| Risk | Mitigation | Residual |
|---|---|---|
| Coordinator sees output | Threshold output decryption (future) | Output is visible to coordinator |
| Trusted dealer for triples | Distribute triple generation (future SPDZ-style) | Coordinator knows all triples |
| No MAC on shares | Add SPDZ-style MAC (future Phase III) | Malicious custodian → wrong result |
| Budget circumvention via Sybil | Identity binding to real credentials | Determined adversary can create identities |

---

## 7. Concrete Security Parameters

For the current deployment ($p = 2^{127}-1$, $K=2$, $N=3$):

| Parameter | Value | Security Level |
|---|---|---|
| Field size | $2^{127} - 1$ | 127-bit information-theoretic |
| Shares needed to reconstruct | $K = 2$ | 1-compromise tolerance |
| Probability of guessing a share | $1/p \approx 2^{-127}$ | Negligible |
| Resharing forward security gap | $(K-1)/p \approx 2^{-127}$ | Negligible |
| HMAC key length | 256 bits | 128-bit computational security |
| Beaver triple randomness | $\log_2(p) = 127$ bits | Uniform over $\mathbb{F}_p$ |

---

## 8. References

1. Shamir, A. "How to share a secret." *Communications of the ACM*, 1979.
2. Beaver, D. "Efficient multiparty protocols using circuit randomization." *CRYPTO*, 1991.
3. Damgård, I. et al. "Multiparty computation from somewhat homomorphic encryption." *CRYPTO*, 2012. (SPDZ)
4. Keller, M. et al. "Overdrive: Making SPDZ Great Again." *EUROCRYPT*, 2018.
5. Herzberg, A. et al. "Proactive secret sharing, or: How to cope with perpetual leakage." *CRYPTO*, 1995.
6. Valiant, L. "A theory of the learnable." *Communications of the ACM*, 1984. (PAC learning)
