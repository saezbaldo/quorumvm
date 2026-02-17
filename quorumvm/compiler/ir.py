"""Intermediate representation for the DAG-based DSL.

Every program compiles to a list of ``Node`` objects plus designated
output node(s).  Node types:

  input  – external input wire
  const  – constant field element
  add    – field addition of two wires
  sub    – field subtraction of two wires
  mul    – field multiplication of two wires
  neg    – additive inverse of one wire
  mux    – selector-based conditional: mux(s, a, b) = s*a + (1-s)*b

Multi-output: ``output_node_ids`` is a list.  For backward compatibility,
``output_node_id`` returns the first (or only) output.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel


class Node(BaseModel):
    """A single node in the computation DAG."""

    id: str
    type: str  # "input" | "const" | "add" | "sub" | "mul" | "neg" | "mux"
    op: Optional[str] = None  # operation name (same as type for ops)
    inputs: List[str] = []  # ids of input nodes
    value: Optional[int] = None  # only for const nodes

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(exclude_none=True)


class IR(BaseModel):
    """Complete intermediate representation.

    Supports single or multiple outputs.  ``output_node_id`` is kept for
    backward compatibility and always returns the first output.
    ``output_node_ids`` holds the full list.
    """

    nodes: List[Node]
    # Primary field: list of output node IDs
    output_node_ids: List[str] = []
    # Legacy single-output field (read-only computed property via validator)
    output_node_id: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        """Synchronise legacy single-output field with the list."""
        if self.output_node_ids and not self.output_node_id:
            self.output_node_id = self.output_node_ids[0]
        elif self.output_node_id and not self.output_node_ids:
            self.output_node_ids = [self.output_node_id]

    @property
    def multi_output(self) -> bool:
        return len(self.output_node_ids) > 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "output_node_id": self.output_node_id,
            "output_node_ids": list(self.output_node_ids),
        }
