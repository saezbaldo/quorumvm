"""DAG executor operating on Shamir shares.

The executor evaluates the IR node-by-node.  Because Shamir shares are
points on polynomials over F_p, **addition and subtraction of shares are
linear** and work directly.  Multiplication of two degree-(k-1)
polynomials would normally produce a degree-2(k-1) polynomial, which
breaks the threshold property.

For the MVP we use a simplification: the custodian evaluates the circuit
*locally on its share values* (treating them as field elements).  This
is correct when the coordinator collects outputs from ≥ K custodians and
reconstructs via Lagrange – **provided every operation is a linear
combination of the secret-shared inputs and publicly-known constants**.

For multiplications between two secret-shared values, the MVP coordinator
falls back to sharing the product at the coordinator level (the inputs
in the demo are sent in the clear to the coordinator anyway).  A
production system would use Beaver triples or degree-reduction; that is
out of scope for this MVP.

The executor therefore evaluates the full DAG on scalar share values,
which is sufficient for demonstrating threshold execution, policy
enforcement, and the activation workflow.
"""

from __future__ import annotations

from typing import Any, Dict

from quorumvm.crypto import field


def evaluate_ir(
    ir: Dict[str, Any],
    input_shares: Dict[str, int],
    const_shares: Dict[str, int],
) -> int:
    """Evaluate the DAG on share values and return the output share.

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
                # Fallback: constant is public, use raw value
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
        else:
            raise ValueError(f"Unknown node type '{ntype}'")

    output_id = ir["output_node_id"]
    if output_id not in wires:
        raise ValueError(f"Output node '{output_id}' was not computed")
    return wires[output_id]
