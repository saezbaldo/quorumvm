"""Tests for the custodian executor."""

from quorumvm.compiler.dsl_parser import compile_source
from quorumvm.config import PRIME
from quorumvm.crypto import field
from quorumvm.custodian.executor import evaluate_ir, evaluate_ir_multi


SAMPLE = """\
input x
const c = 7
add t = x c
mul y = t t
output y
"""


def test_evaluate_plain():
    """Evaluate the DAG on plain (un-shared) values and check the result."""
    ir = compile_source(SAMPLE)
    ir_dict = ir.to_dict()

    x_val = 3
    result = evaluate_ir(ir_dict, {"x": x_val}, {})
    expected = ((x_val + 7) ** 2) % PRIME
    assert result == expected


def test_evaluate_zero():
    ir = compile_source(SAMPLE)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"x": 0}, {})
    assert result == (7 * 7) % PRIME


def test_evaluate_sub():
    src = "input a\nconst b = 5\nsub c = a b\noutput c"
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"a": 10}, {})
    assert result == 5


def test_evaluate_large_value():
    ir = compile_source(SAMPLE)
    ir_dict = ir.to_dict()
    x_val = PRIME - 1
    result = evaluate_ir(ir_dict, {"x": x_val}, {})
    expected = (((PRIME - 1) + 7) ** 2) % PRIME
    assert result == expected


# ===========================================================================
# Phase 9: New gate types
# ===========================================================================


def test_evaluate_neg():
    """neg(x) should give PRIME - x."""
    src = "input x\nneg y = x\noutput y"
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"x": 42}, {})
    assert result == field.neg(42)


def test_evaluate_mux_select_a():
    """mux(1, a, b) = a."""
    src = "input s\ninput a\ninput b\nmux r = s a b\noutput r"
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"s": 1, "a": 100, "b": 200}, {})
    assert result == 100


def test_evaluate_mux_select_b():
    """mux(0, a, b) = b."""
    src = "input s\ninput a\ninput b\nmux r = s a b\noutput r"
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"s": 0, "a": 100, "b": 200}, {})
    assert result == 200


def test_evaluate_mux_interpolated():
    """mux(s, a, b) = s*a + (1-s)*b for arbitrary s."""
    src = "input s\ninput a\ninput b\nmux r = s a b\noutput r"
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    # s=3, a=10, b=20 → 3*10 + (1-3)*20 = 30 + (-2)*20 = 30-40 = -10 mod p
    result = evaluate_ir(ir_dict, {"s": 3, "a": 10, "b": 20}, {})
    expected = (3 * 10 + (1 - 3) * 20) % PRIME
    assert result == expected


# ===========================================================================
# Phase 9: Multi-output
# ===========================================================================


def test_evaluate_multi_output():
    src = """\
input x
const c = 3
add a = x c
mul b = x c
output a b
"""
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    results = evaluate_ir_multi(ir_dict, {"x": 10}, {})
    assert results["a"] == 13  # 10 + 3
    assert results["b"] == 30  # 10 * 3


def test_evaluate_multi_output_single_fallback():
    """evaluate_ir_multi works with single output too."""
    ir = compile_source(SAMPLE)
    ir_dict = ir.to_dict()
    results = evaluate_ir_multi(ir_dict, {"x": 3}, {})
    assert "y" in results
    assert results["y"] == ((3 + 7) ** 2) % PRIME


# ===========================================================================
# Phase 9: Stdlib — dot product and polyeval
# ===========================================================================


def test_evaluate_dot_product():
    """dot(a1, b1, a2, b2) = a1*b1 + a2*b2."""
    src = """\
input a1
input b1
input a2
input b2
dot result = a1 b1 a2 b2
output result
"""
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"a1": 3, "b1": 4, "a2": 5, "b2": 6}, {})
    assert result == (3 * 4 + 5 * 6) % PRIME  # 12 + 30 = 42


def test_evaluate_polyeval():
    """polyeval p = x c0 c1 c2 → c0 + c1*x + c2*x^2."""
    src = """\
input x
const c0 = 1
const c1 = 2
const c2 = 3
polyeval p = x c0 c1 c2
output p
"""
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    # p(5) = 1 + 2*5 + 3*25 = 1 + 10 + 75 = 86
    result = evaluate_ir(ir_dict, {"x": 5}, {})
    assert result == 86


def test_evaluate_polyeval_degree_1():
    """polyeval p = x c0 c1 → c0 + c1*x."""
    src = """\
input x
const c0 = 10
const c1 = 3
polyeval p = x c0 c1
output p
"""
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"x": 7}, {})
    assert result == 31  # 10 + 3*7


def test_evaluate_polyeval_constant():
    """polyeval with single coefficient = c0."""
    src = """\
input x
const c0 = 42
polyeval p = x c0
output p
"""
    ir = compile_source(src)
    ir_dict = ir.to_dict()
    result = evaluate_ir(ir_dict, {"x": 999}, {})
    assert result == 42
