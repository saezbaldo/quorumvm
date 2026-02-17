"""DAG executor operating on Shamir shares with Beaver triple support.

The executor evaluates the IR node-by-node.  Because Shamir shares are
points on polynomials over F_p, **addition and subtraction of shares are
linear** and work directly on shares.

**Multiplication** of two secret-shared values uses the **Beaver triple
protocol** — a two-round interactive procedure between custodians and the
coordinator.  The executor supports two modes:

1. **Full-DAG evaluation** (``evaluate_ir``): evaluates the entire DAG
   in one pass, suitable for programs with only linear ops or for
   backward-compatible plain-value evaluation.

2. **Step-by-step evaluation** (``StepExecutor``): evaluates the DAG
   node-by-node.  When it encounters a ``mul`` node it **pauses** and
   emits a ``MulRequest`` that the coordinator uses to orchestrate the
   Beaver protocol.  After the coordinator resolves the masked values
   and sends them back, the executor resumes.

Supported node types: input, const, add, sub, mul, neg, mux.

The ``mux`` node implements ``mux(s, a, b) = s*a + (1-s)*b`` and
decomposes into two multiplications internally.

The step-by-step mode is used by the Beaver-aware coordinator endpoint
to achieve true secure multiplication on shares.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional, Tuple

from quorumvm.crypto import field
from quorumvm.crypto.beaver import custodian_mul_round1, custodian_mul_round2


# --------------------------------------------------------------------------
# Data classes for the step-by-step protocol
# --------------------------------------------------------------------------


@dataclass
class MulRequest:
    """Emitted by StepExecutor when it hits a ``mul`` node.

    The coordinator collects these from all custodians and runs the
    Beaver protocol to resolve the multiplication.
    """

    node_id: str
    epsilon_share: int  # share of (x - a)
    delta_share: int    # share of (y - b)


@dataclass
class MulResolution:
    """Sent by the coordinator back to the custodian after Round 1.

    Contains the publicly-reconstructed masked values ε and δ, plus
    the custodian's Beaver shares (a_i, b_i, c_i) for Round 2.
    """

    node_id: str
    epsilon: int  # reconstructed ε = x - a
    delta: int    # reconstructed δ = y - b


# --------------------------------------------------------------------------
# Step-by-step executor (Beaver-aware)
# --------------------------------------------------------------------------


class StepExecutor:
    """Evaluates an IR DAG node-by-node, pausing at ``mul`` nodes.

    Usage::

        exec = StepExecutor(ir, input_shares, const_shares, beaver_shares)
        while not exec.done:
            mul_reqs = exec.step()
            if mul_reqs:
                # send mul_reqs to coordinator, get resolutions back
                exec.resolve_muls(resolutions)
        output = exec.output()
    """

    def __init__(
        self,
        ir: Dict[str, Any],
        input_shares: Dict[str, int],
        const_shares: Dict[str, int],
        beaver_shares: Optional[Dict[str, Dict[str, Tuple[int, int]]]] = None,
    ) -> None:
        """
        Parameters
        ----------
        ir : dict
            The IR dict with ``nodes`` and ``output_node_id``.
        input_shares : dict
            var_name → share y-value.
        const_shares : dict
            const_node_id → share y-value (or fall back to public).
        beaver_shares : dict or None
            mul_node_id → {"a": (x,y), "b": (x,y), "c": (x,y)}.
            If None, mul falls back to plain multiplication (legacy mode).
        """
        self.ir = ir
        self.wires: Dict[str, int] = {}
        self.input_shares = input_shares
        self.const_shares = const_shares
        self.beaver_shares = beaver_shares or {}
        self._nodes = list(ir["nodes"])
        self._cursor = 0
        self.done = False
        self._pending_muls: List[str] = []

    def step(self) -> List[MulRequest]:
        """Evaluate nodes until a ``mul`` is encountered or DAG is done.

        Returns a list of MulRequest objects (one per mul node hit in
        this step).  If the list is empty, the DAG evaluation is
        complete.
        """
        mul_requests: List[MulRequest] = []

        while self._cursor < len(self._nodes):
            node = self._nodes[self._cursor]
            nid = node["id"]
            ntype = node["type"]

            if ntype == "input":
                if nid not in self.input_shares:
                    raise ValueError(f"Missing input share for '{nid}'")
                self.wires[nid] = self.input_shares[nid]
                self._cursor += 1

            elif ntype == "const":
                if nid in self.const_shares:
                    self.wires[nid] = self.const_shares[nid]
                else:
                    self.wires[nid] = field.reduce(node["value"])
                self._cursor += 1

            elif ntype in ("add", "sub"):
                a_id, b_id = node["inputs"]
                a_val, b_val = self.wires[a_id], self.wires[b_id]
                if ntype == "add":
                    self.wires[nid] = field.add(a_val, b_val)
                else:
                    self.wires[nid] = field.sub(a_val, b_val)
                self._cursor += 1

            elif ntype == "neg":
                a_id = node["inputs"][0]
                self.wires[nid] = field.neg(self.wires[a_id])
                self._cursor += 1

            elif ntype == "mux":
                # mux(s, a, b) = s*a + (1-s)*b
                # Treated as two mul nodes for Beaver purposes.
                # The compiler should have already expanded mux into
                # mul + mul + add in the IR, but we also support
                # native mux nodes that get decomposed at eval time.
                # For the StepExecutor, mux with Beaver is handled
                # by decomposing into two synthetic mul nodes at
                # compile time.  If we hit a native mux here,
                # we do a plain evaluation (legacy / non-Beaver mode).
                s_id, a_id, b_id = node["inputs"]
                s_val = self.wires[s_id]
                a_val = self.wires[a_id]
                b_val = self.wires[b_id]
                # Plain evaluation: s*a + (1-s)*b
                sa = field.mul(s_val, a_val)
                one_minus_s = field.sub(1, s_val)
                sb = field.mul(one_minus_s, b_val)
                self.wires[nid] = field.add(sa, sb)
                self._cursor += 1

            elif ntype == "mul":
                a_id, b_id = node["inputs"]
                x_share = self.wires[a_id]
                y_share = self.wires[b_id]

                if nid in self.beaver_shares:
                    # --- Beaver Round 1 ---
                    bshares = self.beaver_shares[nid]
                    a_y = bshares["a"][1]
                    b_y = bshares["b"][1]
                    eps, delta = custodian_mul_round1(
                        x_share, y_share, a_y, b_y,
                    )
                    mul_requests.append(MulRequest(
                        node_id=nid,
                        epsilon_share=eps,
                        delta_share=delta,
                    ))
                    self._pending_muls.append(nid)
                    self._cursor += 1
                else:
                    # Legacy fallback: plain multiplication (no Beaver)
                    self.wires[nid] = field.mul(x_share, y_share)
                    self._cursor += 1
            else:
                raise ValueError(f"Unknown node type '{ntype}'")

            # If we hit mul nodes with Beaver, pause to let coordinator
            # orchestrate the protocol.  We batch all consecutive muls.
            if mul_requests:
                # Look ahead: if the next node is also a mul whose inputs
                # are already resolved, continue to batch it.
                if self._cursor < len(self._nodes):
                    next_node = self._nodes[self._cursor]
                    if next_node["type"] == "mul":
                        next_inputs = next_node["inputs"]
                        if all(i in self.wires for i in next_inputs):
                            continue  # batch this mul too
                # Otherwise break and return the batch
                return mul_requests

        self.done = True
        return []

    def resolve_muls(self, resolutions: List[MulResolution]) -> None:
        """Apply Beaver Round-2 results for pending mul nodes.

        Parameters
        ----------
        resolutions : list of MulResolution
            Must be in the same order as the MulRequests returned by step().
        """
        for res in resolutions:
            nid = res.node_id
            if nid not in self.beaver_shares:
                raise ValueError(f"No Beaver shares for node '{nid}'")
            bshares = self.beaver_shares[nid]
            z_share = custodian_mul_round2(
                epsilon=res.epsilon,
                delta=res.delta,
                a_share_y=bshares["a"][1],
                b_share_y=bshares["b"][1],
                c_share_y=bshares["c"][1],
            )
            self.wires[nid] = z_share
        self._pending_muls.clear()

    def output(self) -> int:
        """Return the output wire value (call after ``done`` is True).

        Returns the first (or only) output.  For multi-output programs
        use ``outputs()``.
        """
        output_id = self.ir.get("output_node_id") or self.ir.get("output_node_ids", [None])[0]
        if output_id is None or output_id not in self.wires:
            raise RuntimeError("Output node not yet evaluated")
        return self.wires[output_id]

    def outputs(self) -> Dict[str, int]:
        """Return all output wire values as {name: value} dict.

        Falls back to single-output if ``output_node_ids`` is absent.
        """
        ids = self.ir.get("output_node_ids", [])
        if not ids:
            oid = self.ir.get("output_node_id")
            if oid:
                ids = [oid]
        result: Dict[str, int] = {}
        for oid in ids:
            if oid not in self.wires:
                raise RuntimeError(f"Output node '{oid}' not yet evaluated")
            result[oid] = self.wires[oid]
        return result


# --------------------------------------------------------------------------
# Legacy one-shot evaluator (backward compatible)
# --------------------------------------------------------------------------


def evaluate_ir(
    ir: Dict[str, Any],
    input_shares: Dict[str, int],
    const_shares: Dict[str, int],
) -> int:
    """Evaluate the DAG on share values and return the output share.

    This is the legacy one-shot evaluator that does **not** use Beaver
    triples.  It evaluates ``mul`` as plain field multiplication, which
    is correct when all custodians receive the same plain inputs (the
    original MVP behavior).

    Parameters
    ----------
    ir : dict
        The IR dictionary (``nodes`` + ``output_node_id``).
    input_shares : dict
        Mapping of input-node id → share value (int).
    const_shares : dict
        Mapping of const-node id → share of the constant.
    """
    wires: Dict[str, int] = {}

    for node in ir["nodes"]:
        nid = node["id"]
        ntype = node["type"]

        if ntype == "input":
            if nid not in input_shares:
                raise ValueError(f"Missing input share for '{nid}'")
            wires[nid] = input_shares[nid]

        elif ntype == "const":
            if nid in const_shares:
                wires[nid] = const_shares[nid]
            else:
                wires[nid] = field.reduce(node["value"])

        elif ntype in ("add", "sub", "mul"):
            a_id, b_id = node["inputs"]
            a_val = wires[a_id]
            b_val = wires[b_id]
            if ntype == "add":
                wires[nid] = field.add(a_val, b_val)
            elif ntype == "sub":
                wires[nid] = field.sub(a_val, b_val)
            elif ntype == "mul":
                wires[nid] = field.mul(a_val, b_val)

        elif ntype == "neg":
            a_id = node["inputs"][0]
            wires[nid] = field.neg(wires[a_id])

        elif ntype == "mux":
            s_id, a_id, b_id = node["inputs"]
            s_val = wires[s_id]
            a_val = wires[a_id]
            b_val = wires[b_id]
            sa = field.mul(s_val, a_val)
            one_minus_s = field.sub(1, s_val)
            sb = field.mul(one_minus_s, b_val)
            wires[nid] = field.add(sa, sb)

        else:
            raise ValueError(f"Unknown node type '{ntype}'")

    output_id = ir.get("output_node_id") or ir.get("output_node_ids", [None])[0]
    if output_id is None or output_id not in wires:
        raise ValueError(f"Output node '{output_id}' was not computed")
    return wires[output_id]


def evaluate_ir_multi(
    ir: Dict[str, Any],
    input_shares: Dict[str, int],
    const_shares: Dict[str, int],
) -> Dict[str, int]:
    """Evaluate the DAG and return all output shares as {name: value}.

    This is the multi-output variant of ``evaluate_ir``.
    """
    wires: Dict[str, int] = {}

    for node in ir["nodes"]:
        nid = node["id"]
        ntype = node["type"]

        if ntype == "input":
            if nid not in input_shares:
                raise ValueError(f"Missing input share for '{nid}'")
            wires[nid] = input_shares[nid]

        elif ntype == "const":
            if nid in const_shares:
                wires[nid] = const_shares[nid]
            else:
                wires[nid] = field.reduce(node["value"])

        elif ntype in ("add", "sub", "mul"):
            a_id, b_id = node["inputs"]
            a_val = wires[a_id]
            b_val = wires[b_id]
            if ntype == "add":
                wires[nid] = field.add(a_val, b_val)
            elif ntype == "sub":
                wires[nid] = field.sub(a_val, b_val)
            elif ntype == "mul":
                wires[nid] = field.mul(a_val, b_val)

        elif ntype == "neg":
            a_id = node["inputs"][0]
            wires[nid] = field.neg(wires[a_id])

        elif ntype == "mux":
            s_id, a_id, b_id = node["inputs"]
            s_val = wires[s_id]
            a_val = wires[a_id]
            b_val = wires[b_id]
            sa = field.mul(s_val, a_val)
            one_minus_s = field.sub(1, s_val)
            sb = field.mul(one_minus_s, b_val)
            wires[nid] = field.add(sa, sb)

        else:
            raise ValueError(f"Unknown node type '{ntype}'")

    output_ids = ir.get("output_node_ids", [])
    if not output_ids:
        oid = ir.get("output_node_id")
        if oid:
            output_ids = [oid]

    results: Dict[str, int] = {}
    for oid in output_ids:
        if oid not in wires:
            raise ValueError(f"Output node '{oid}' was not computed")
        results[oid] = wires[oid]
    return results
