"""DSL parser – compiles the tiny declarative language to IR.

Grammar (one statement per line, blank lines / ``#`` comments ignored):

    input <name>
    const <name> = <int_literal>
    add   <name> = <arg1> <arg2>
    sub   <name> = <arg1> <arg2>
    mul   <name> = <arg1> <arg2>
    neg   <name> = <arg>
    mux   <name> = <selector> <a> <b>
    output <name> [<name2> ...]

Stdlib macros (expanded inline during compilation):

    dot <name> = <a1> <b1> <a2> <b2> [... <aN> <bN>]
    polyeval <name> = <x> <c0> <c1> [... <cN>]

The parser enforces:
- No duplicate identifiers
- All referenced identifiers must be defined before use
- At least one ``output`` statement
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
    output_names: List[str] = []

    # Internal counter for synthesised names in macros
    _synth = {"counter": 0}

    def _synth_name(prefix: str) -> str:
        _synth["counter"] += 1
        return f"__{prefix}_{_synth['counter']}"

    def _add_node(node: Node) -> None:
        nodes.append(node)
        defined[node.id] = node

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
                _add_node(node)

            elif keyword == "const":
                # const <name> = <value>
                name = tokens[1]
                _check_dup(name, defined, lineno)
                value = int(tokens[3])
                node = Node(id=name, type="const", value=value)
                _add_node(node)

            elif keyword in ("add", "sub", "mul"):
                # <op> <name> = <a> <b>
                name = tokens[1]
                _check_dup(name, defined, lineno)
                a, b = tokens[3], tokens[4]
                _check_ref(a, defined, lineno)
                _check_ref(b, defined, lineno)
                node = Node(id=name, type=keyword, op=keyword, inputs=[a, b])
                _add_node(node)

            elif keyword == "neg":
                # neg <name> = <arg>
                name = tokens[1]
                _check_dup(name, defined, lineno)
                arg = tokens[3]
                _check_ref(arg, defined, lineno)
                node = Node(id=name, type="neg", op="neg", inputs=[arg])
                _add_node(node)

            elif keyword == "mux":
                # mux <name> = <selector> <a> <b>
                # Expands to: s*a + (1-s)*b
                name = tokens[1]
                _check_dup(name, defined, lineno)
                sel, a, b = tokens[3], tokens[4], tokens[5]
                _check_ref(sel, defined, lineno)
                _check_ref(a, defined, lineno)
                _check_ref(b, defined, lineno)
                node = Node(id=name, type="mux", op="mux", inputs=[sel, a, b])
                _add_node(node)

            elif keyword == "dot":
                # dot <name> = <a1> <b1> <a2> <b2> ... <aN> <bN>
                name = tokens[1]
                _check_dup(name, defined, lineno)
                args = tokens[3:]
                if len(args) < 2 or len(args) % 2 != 0:
                    raise DSLCompileError(
                        f"Line {lineno}: dot requires even number of args (pairs)"
                    )
                for arg in args:
                    _check_ref(arg, defined, lineno)

                # Expand to mul + add chain
                pairs = [(args[i], args[i + 1]) for i in range(0, len(args), 2)]
                partial_names: List[str] = []
                for i, (ai, bi) in enumerate(pairs):
                    mul_name = _synth_name(f"dot_{name}_m")
                    mul_node = Node(id=mul_name, type="mul", op="mul", inputs=[ai, bi])
                    _add_node(mul_node)
                    partial_names.append(mul_name)

                # Sum all partials
                acc = partial_names[0]
                for i in range(1, len(partial_names)):
                    if i == len(partial_names) - 1:
                        add_name = name  # Final sum gets the user's chosen name
                    else:
                        add_name = _synth_name(f"dot_{name}_s")
                    add_node = Node(id=add_name, type="add", op="add", inputs=[acc, partial_names[i]])
                    _add_node(add_node)
                    acc = add_name

                # Edge case: single pair → rename isn't possible,
                # so if only one pair the mul node itself suffices.
                if len(partial_names) == 1:
                    # We already created the mul node with a synthetic name.
                    # Create an add with zero to alias it to the user's name.
                    zero_name = _synth_name(f"dot_{name}_z")
                    zero_node = Node(id=zero_name, type="const", value=0)
                    _add_node(zero_node)
                    alias_node = Node(id=name, type="add", op="add", inputs=[partial_names[0], zero_name])
                    _add_node(alias_node)

            elif keyword == "polyeval":
                # polyeval <name> = <x> <c0> <c1> ... <cN>
                # Evaluates c0 + c1*x + c2*x^2 + ... + cN*x^N using Horner's method
                # Horner: (...((cN * x + c_{N-1}) * x + c_{N-2}) * x + ... ) * x + c0
                name = tokens[1]
                _check_dup(name, defined, lineno)
                args = tokens[3:]
                if len(args) < 2:
                    raise DSLCompileError(
                        f"Line {lineno}: polyeval requires at least x and one coefficient"
                    )
                x_var = args[0]
                _check_ref(x_var, defined, lineno)
                coeffs = args[1:]  # c0, c1, ..., cN
                for c in coeffs:
                    _check_ref(c, defined, lineno)

                if len(coeffs) == 1:
                    # Constant polynomial: result = c0
                    zero_name = _synth_name(f"poly_{name}_z")
                    zero_node = Node(id=zero_name, type="const", value=0)
                    _add_node(zero_node)
                    alias_node = Node(id=name, type="add", op="add", inputs=[coeffs[0], zero_name])
                    _add_node(alias_node)
                else:
                    # Horner's method: start from the highest coefficient
                    # acc = cN
                    acc = coeffs[-1]
                    for i in range(len(coeffs) - 2, -1, -1):
                        # acc = acc * x + c_i
                        mul_name = _synth_name(f"poly_{name}_m")
                        mul_node = Node(id=mul_name, type="mul", op="mul", inputs=[acc, x_var])
                        _add_node(mul_node)

                        if i == 0:
                            add_name = name  # Final result gets user's name
                        else:
                            add_name = _synth_name(f"poly_{name}_a")
                        add_node = Node(id=add_name, type="add", op="add", inputs=[mul_name, coeffs[i]])
                        _add_node(add_node)
                        acc = add_name

            elif keyword == "output":
                # output <name1> [<name2> ...]
                names = tokens[1:]
                for oname in names:
                    _check_ref(oname, defined, lineno)
                    if oname in output_names:
                        raise DSLCompileError(
                            f"Line {lineno}: duplicate output '{oname}'"
                        )
                    output_names.append(oname)

            else:
                raise DSLCompileError(f"Line {lineno}: unknown keyword '{keyword}'")

        except IndexError:
            raise DSLCompileError(f"Line {lineno}: incomplete statement")

    if not output_names:
        raise DSLCompileError("No output statement found")

    return IR(nodes=nodes, output_node_ids=output_names)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _check_dup(name: str, defined: dict, lineno: int) -> None:
    if name in defined:
        raise DSLCompileError(f"Line {lineno}: duplicate identifier '{name}'")


def _check_ref(name: str, defined: dict, lineno: int) -> None:
    if name not in defined:
        raise DSLCompileError(f"Line {lineno}: undefined identifier '{name}'")
