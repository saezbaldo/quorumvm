"""DSL parser – compiles the tiny declarative language to IR.

Grammar (one statement per line, blank lines / ``#`` comments ignored):

    input <name>
    const <name> = <int_literal>
    add   <name> = <arg1> <arg2>
    sub   <name> = <arg1> <arg2>
    mul   <name> = <arg1> <arg2>
    output <name>

The parser enforces:
- No duplicate identifiers
- All referenced identifiers must be defined before use
- Exactly one ``output`` statement
- No loops / recursion (guaranteed by define-before-use)
"""

from __future__ import annotations

from typing import List

from quorumvm.compiler.ir import IR, Node


class DSLCompileError(Exception):
    """Raised when the DSL source is invalid."""


def compile_source(source: str) -> IR:
    """Parse DSL *source* text and return an ``IR``."""
    nodes: List[Node] = []
    defined: dict[str, Node] = {}
    output_name: str | None = None

    for lineno, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        keyword = tokens[0].lower()

        try:
            if keyword == "input":
                name = tokens[1]
                _check_dup(name, defined, lineno)
                node = Node(id=name, type="input")
                nodes.append(node)
                defined[name] = node

            elif keyword == "const":
                # const <name> = <value>
                name = tokens[1]
                _check_dup(name, defined, lineno)
                value = int(tokens[3])
                node = Node(id=name, type="const", value=value)
                nodes.append(node)
                defined[name] = node

            elif keyword in ("add", "sub", "mul"):
                # <op> <name> = <a> <b>
                name = tokens[1]
                _check_dup(name, defined, lineno)
                a, b = tokens[3], tokens[4]
                _check_ref(a, defined, lineno)
                _check_ref(b, defined, lineno)
                node = Node(id=name, type=keyword, op=keyword, inputs=[a, b])
                nodes.append(node)
                defined[name] = node

            elif keyword == "output":
                name = tokens[1]
                _check_ref(name, defined, lineno)
                if output_name is not None:
                    raise DSLCompileError(
                        f"Line {lineno}: multiple outputs (already declared '{output_name}')"
                    )
                output_name = name

            else:
                raise DSLCompileError(f"Line {lineno}: unknown keyword '{keyword}'")

        except IndexError:
            raise DSLCompileError(f"Line {lineno}: incomplete statement")

    if output_name is None:
        raise DSLCompileError("No output statement found")

    return IR(nodes=nodes, output_node_id=output_name)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _check_dup(name: str, defined: dict, lineno: int) -> None:
    if name in defined:
        raise DSLCompileError(f"Line {lineno}: duplicate identifier '{name}'")


def _check_ref(name: str, defined: dict, lineno: int) -> None:
    if name not in defined:
        raise DSLCompileError(f"Line {lineno}: undefined identifier '{name}'")
