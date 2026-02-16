"""Tests for the custodian executor."""

from quorumvm.compiler.dsl_parser import compile_source
from quorumvm.config import PRIME
from quorumvm.crypto import field
from quorumvm.custodian.executor import evaluate_ir


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
