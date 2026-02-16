"""Intermediate representation for the DAG-based DSL.

Every program compiles to a list of ``Node`` objects plus a designated
output node.  Node types:

  input  – external input wire
  const  – constant field element
  add    – field addition of two wires
  sub    – field subtraction of two wires
  mul    – field multiplication of two wires
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class Node(BaseModel):
    """A single node in the computation DAG."""

    id: str
    type: str  # "input" | "const" | "add" | "sub" | "mul"
    op: Optional[str] = None  # operation name (same as type for ops)
    inputs: List[str] = []  # ids of input nodes
    value: Optional[int] = None  # only for const nodes

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(exclude_none=True)


class IR(BaseModel):
    """Complete intermediate representation."""

    nodes: List[Node]
    output_node_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "output_node_id": self.output_node_id,
        }
