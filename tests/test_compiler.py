"""Tests for the DSL compiler."""

import pytest

from quorumvm.compiler.dsl_parser import DSLCompileError, compile_source


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


def test_multiple_outputs():
    with pytest.raises(DSLCompileError, match="multiple outputs"):
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
    assert len(d["nodes"]) == 4
