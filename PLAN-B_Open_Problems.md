# PLAN-B: Open Research Problems (QuorumVM)

This list is designed to attract collaborators from MPC, cryptography, distributed systems, and security engineering.

## A) Oracle-limited extraction formalization
1. Define “functional extraction” under bounded queries:
   - exact equivalence vs approximation
   - metrics for generalization error
2. Lower bounds: How many queries are required to approximate a DSL-class function under noise-free outputs?
3. Optimal policies: budgets/rate limits that maximize deterrence while preserving utility.

## B) DSL expressiveness vs extractability
4. What minimal DSL features sharply increase learnability by black-box approximation?
5. Are there DSL subsets with provably hard extraction under bounded queries?
6. Conditionals and branching: impacts on learnability and protocol cost.

## C) Threshold governance and long-term compromise
7. Proactive resharing schedules vs operational cost.
8. Custodian churn: best practices for onboarding/offboarding without downtime.
9. Adversary over time: partial compromise accumulation and defense via rotation.

## D) Practical hardening
10. Audit log designs that are tamper-evident and privacy-preserving.
11. Attestation integration (optional): how much security gain per complexity.
12. Detection: distinguishing legitimate workload from extraction sweeps.

## E) Economics as defense
13. Ticketing markets: cost per eval tuned against extraction value.
14. Adaptive pricing policies under suspected extraction.

## F) Benchmarks
15. Standard test suite for “extraction pressure”:
   - query strategies
   - reconstruction attempts
   - approximation success curves under budget caps
