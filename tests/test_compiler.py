"""Tests for the DSL compiler."""

import pytest

from quorumvm.compiler.dsl_parser import DSLCompileError, compile_source
from quorumvm.compiler.optimizer import (
    eliminate_common_subexpressions,
    optimize,
    prune_dead_nodes,
)
from quorumvm.config import PRIME


SAMPLE = """\
input x
const c = 7
add t = x c
mul y = t t
output y
"""


def test_compile_sample():
    ir = compile_source(SAMPLE)
    assert len(ir.nodes) == 4
    assert ir.output_node_id == "y"


def test_node_types():
    ir = compile_source(SAMPLE)
    types = {n.id: n.type for n in ir.nodes}
    assert types["x"] == "input"
    assert types["c"] == "const"
    assert types["t"] == "add"
    assert types["y"] == "mul"


def test_const_value():
    ir = compile_source(SAMPLE)
    const_node = next(n for n in ir.nodes if n.id == "c")
    assert const_node.value == 7


def test_op_inputs():
    ir = compile_source(SAMPLE)
    add_node = next(n for n in ir.nodes if n.id == "t")
    assert add_node.inputs == ["x", "c"]


def test_missing_output():
    with pytest.raises(DSLCompileError, match="No output"):
        compile_source("input x\nconst c = 1\nadd t = x c")


def test_duplicate_identifier():
    with pytest.raises(DSLCompileError, match="duplicate"):
        compile_source("input x\ninput x\noutput x")


def test_undefined_reference():
    with pytest.raises(DSLCompileError, match="undefined"):
        compile_source("input x\nadd t = x z\noutput t")


def test_multiple_outputs_same_name():
    with pytest.raises(DSLCompileError, match="duplicate output"):
        compile_source("input x\noutput x\noutput x")


def test_comments_and_blanks():
    src = """
    # This is a comment
    input a

    const b = 3
    add c = a b
    output c
    """
    ir = compile_source(src)
    assert ir.output_node_id == "c"


def test_sub_op():
    src = "input a\nconst b = 2\nsub c = a b\noutput c"
    ir = compile_source(src)
    sub_node = next(n for n in ir.nodes if n.id == "c")
    assert sub_node.type == "sub"


def test_ir_to_dict():
    ir = compile_source(SAMPLE)
    d = ir.to_dict()
    assert "nodes" in d
    assert "output_node_id" in d
    assert "output_node_ids" in d
    assert len(d["nodes"]) == 4


# ===========================================================================
# Phase 9: New gate types
# ===========================================================================


def test_neg_gate():
    src = "input x\nneg y = x\noutput y"
    ir = compile_source(src)
    neg_node = next(n for n in ir.nodes if n.id == "y")
    assert neg_node.type == "neg"
    assert neg_node.inputs == ["x"]


def test_mux_gate():
    src = "input s\ninput a\ninput b\nmux r = s a b\noutput r"
    ir = compile_source(src)
    mux_node = next(n for n in ir.nodes if n.id == "r")
    assert mux_node.type == "mux"
    assert mux_node.inputs == ["s", "a", "b"]


# ===========================================================================
# Phase 9: Multi-output
# ===========================================================================


def test_multi_output():
    src = """\
input x
const c = 3
add a = x c
mul b = x c
output a b
"""
    ir = compile_source(src)
    assert ir.output_node_ids == ["a", "b"]
    assert ir.output_node_id == "a"  # first output for backward compat
    assert ir.multi_output is True


def test_single_output_backward_compat():
    ir = compile_source(SAMPLE)
    assert ir.output_node_ids == ["y"]
    assert ir.output_node_id == "y"
    assert ir.multi_output is False


def test_multi_output_separate_lines():
    src = """\
input x
const c = 5
add a = x c
sub b = x c
output a
output b
"""
    ir = compile_source(src)
    assert ir.output_node_ids == ["a", "b"]


# ===========================================================================
# Phase 9: Stdlib macros
# ===========================================================================


def test_dot_product():
    src = """\
input a1
input b1
input a2
input b2
dot result = a1 b1 a2 b2
output result
"""
    ir = compile_source(src)
    # The dot macro expands to mul + mul + add nodes
    node_types = [n.type for n in ir.nodes]
    assert "mul" in node_types
    # The final node named "result" should exist
    assert ir.output_node_id == "result"


def test_dot_product_single_pair():
    src = """\
input a
input b
dot result = a b
output result
"""
    ir = compile_source(src)
    assert ir.output_node_id == "result"


def test_polyeval_horner():
    """polyeval p = x c0 c1 c2 → c0 + c1*x + c2*x^2 via Horner."""
    src = """\
input x
const c0 = 1
const c1 = 2
const c2 = 3
polyeval p = x c0 c1 c2
output p
"""
    ir = compile_source(src)
    assert ir.output_node_id == "p"
    # Should have mul nodes from Horner expansion
    mul_count = sum(1 for n in ir.nodes if n.type == "mul")
    assert mul_count >= 2  # Horner for degree-2 uses 2 muls


def test_polyeval_constant():
    """polyeval with single coefficient = c0."""
    src = """\
input x
const c0 = 42
polyeval p = x c0
output p
"""
    ir = compile_source(src)
    assert ir.output_node_id == "p"


def test_dot_odd_args_error():
    with pytest.raises(DSLCompileError, match="even number"):
        compile_source("input a\ndot r = a\noutput r")


def test_polyeval_no_coeffs_error():
    with pytest.raises(DSLCompileError, match="at least"):
        compile_source("input x\npolyeval p = x\noutput p")


# ===========================================================================
# Phase 9: Compiler optimizations
# ===========================================================================


def test_cse_merges_duplicates():
    """CSE should merge two identical add nodes."""
    src = """\
input x
const c = 5
add a = x c
add b = x c
output a
"""
    ir = compile_source(src)
    optimized = eliminate_common_subexpressions(ir)
    # Both 'a' and 'b' compute the same thing; 'b' should be merged into 'a'
    ids = [n.id for n in optimized.nodes]
    assert "a" in ids
    assert "b" not in ids  # merged away


def test_dead_node_pruning():
    """Dead node pruning should remove nodes not reachable from output."""
    src = """\
input x
const c = 3
add used = x c
mul dead = x c
output used
"""
    ir = compile_source(src)
    pruned = prune_dead_nodes(ir)
    ids = [n.id for n in pruned.nodes]
    assert "used" in ids
    assert "dead" not in ids  # not reachable from output


def test_optimize_combines_cse_and_pruning():
    """Full optimization: CSE + pruning together."""
    src = """\
input x
const c = 3
add a = x c
add b = x c
mul dead = x c
output a
"""
    ir = compile_source(src)
    optimized = optimize(ir)
    ids = [n.id for n in optimized.nodes]
    assert "a" in ids
    assert "b" not in ids   # merged by CSE
    assert "dead" not in ids  # pruned


def test_cse_preserves_different_ops():
    """CSE should NOT merge nodes with different operations."""
    src = """\
input x
const c = 5
add a = x c
mul b = x c
output a
output b
"""
    ir = compile_source(src)
    optimized = eliminate_common_subexpressions(ir)
    ids = [n.id for n in optimized.nodes]
    assert "a" in ids
    assert "b" in ids  # different op → not merged
