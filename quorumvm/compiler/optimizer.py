"""Compiler optimizations for DAG IR.

Implements:
- **Common Subexpression Elimination (CSE)**: detects nodes that compute
  the same operation on the same inputs and merges them into a single
  node, rewriting downstream references.
- **Dead Node Pruning**: removes nodes whose outputs are never used
  (directly or transitively) by any output node.
"""

from __future__ import annotations

from typing import Dict, List, Set

from quorumvm.compiler.ir import IR, Node


def optimize(ir: IR) -> IR:
    """Apply all optimizations and return a new IR."""
    ir = eliminate_common_subexpressions(ir)
    ir = prune_dead_nodes(ir)
    return ir


# ------------------------------------------------------------------
# Common Subexpression Elimination
# ------------------------------------------------------------------

def eliminate_common_subexpressions(ir: IR) -> IR:
    """Merge duplicate computation nodes.

    Two nodes are considered duplicates if they have the same type,
    the same op, the same inputs (order-sensitive), and the same
    value (for consts).
    """
    # signature → canonical node id
    seen: Dict[str, str] = {}
    # old id → canonical id  (identity for non-duplicates)
    remap: Dict[str, str] = {}
    new_nodes: List[Node] = []

    for node in ir.nodes:
        # Remap inputs first
        remapped_inputs = [remap.get(i, i) for i in node.inputs]

        sig = _node_signature(node, remapped_inputs)

        if sig in seen:
            # Duplicate — remap this node's id to the canonical one
            remap[node.id] = seen[sig]
        else:
            seen[sig] = node.id
            remap[node.id] = node.id
            new_node = Node(
                id=node.id,
                type=node.type,
                op=node.op,
                inputs=remapped_inputs,
                value=node.value,
            )
            new_nodes.append(new_node)

    # Remap output node ids
    new_output_ids = [remap.get(oid, oid) for oid in ir.output_node_ids]

    return IR(nodes=new_nodes, output_node_ids=new_output_ids)


def _node_signature(node: Node, remapped_inputs: List[str]) -> str:
    """Create a hashable signature for a node (type + op + inputs + value)."""
    parts = [node.type, node.op or ""]
    parts.extend(remapped_inputs)
    if node.value is not None:
        parts.append(str(node.value))
    return "|".join(parts)


# ------------------------------------------------------------------
# Dead Node Pruning
# ------------------------------------------------------------------

def prune_dead_nodes(ir: IR) -> IR:
    """Remove nodes not reachable from any output node."""
    # Walk backward from outputs to find all live nodes
    live: Set[str] = set()
    node_map: Dict[str, Node] = {n.id: n for n in ir.nodes}

    def _mark_live(nid: str) -> None:
        if nid in live:
            return
        live.add(nid)
        node = node_map.get(nid)
        if node:
            for inp in node.inputs:
                _mark_live(inp)

    for oid in ir.output_node_ids:
        _mark_live(oid)

    new_nodes = [n for n in ir.nodes if n.id in live]
    return IR(nodes=new_nodes, output_node_ids=list(ir.output_node_ids))
