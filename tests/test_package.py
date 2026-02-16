"""Tests for the program package builder."""

from quorumvm.compiler.dsl_parser import compile_source
from quorumvm.compiler.package import PolicyManifest, SecretManifest, build_package


SAMPLE = """\
input x
const c = 7
add t = x c
mul y = t t
output y
"""


def test_package_has_id():
    ir = compile_source(SAMPLE)
    pkg = build_package(ir)
    assert len(pkg.program_id) == 64  # SHA-256 hex


def test_package_deterministic():
    ir = compile_source(SAMPLE)
    pkg1 = build_package(ir, version="1.0.0")
    pkg2 = build_package(ir, version="1.0.0")
    assert pkg1.program_id == pkg2.program_id


def test_different_version_different_id():
    ir = compile_source(SAMPLE)
    pkg1 = build_package(ir, version="1.0.0")
    pkg2 = build_package(ir, version="2.0.0")
    # version is not part of the hash (only ir + manifests)
    # If policy/secret are the same, id should be the same
    # Actually version is NOT in the hash per spec: hash(ir + policy + secret)
    # So these should be equal:
    assert pkg1.program_id == pkg2.program_id


def test_different_policy_different_id():
    ir = compile_source(SAMPLE)
    p1 = PolicyManifest(cost_per_eval=1)
    p2 = PolicyManifest(cost_per_eval=99)
    pkg1 = build_package(ir, policy=p1)
    pkg2 = build_package(ir, policy=p2)
    assert pkg1.program_id != pkg2.program_id


def test_package_contains_ir():
    ir = compile_source(SAMPLE)
    pkg = build_package(ir)
    assert "nodes" in pkg.ir
    assert "output_node_id" in pkg.ir
