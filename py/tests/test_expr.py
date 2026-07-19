from pakeles._expr import FieldSpec
from pakeles._pb import ir_pb2


def make_field(name: str = "ihl", bits: int = 4) -> FieldSpec:
    f = FieldSpec(width_bits=bits, display_name="X")
    f.name = name
    f.header = "ipv4"
    return f


def test_field_arithmetic_builds_operator_tree() -> None:
    ihl = make_field()
    e = (ihl * 4 - 20).to_pb()
    assert e.bin.op == ir_pb2.BIN_OP_KIND_SUB
    assert e.bin.lhs.bin.op == ir_pb2.BIN_OP_KIND_MUL
    assert e.bin.lhs.bin.lhs.field.header == "ipv4"
    assert e.bin.lhs.bin.lhs.field.field == "ihl"
    assert e.bin.lhs.bin.rhs.constant == 4
    assert e.bin.rhs.constant == 20


def test_reverse_ops_and_ints() -> None:
    ihl = make_field()
    e = (4 * ihl).to_pb()
    assert e.bin.lhs.constant == 4
    assert e.bin.rhs.field.field == "ihl"


def test_shift_and_mask_ops() -> None:
    flags = make_field("flags", 8)
    e = ((flags >> 2) & 0x3).to_pb()
    assert e.bin.op == ir_pb2.BIN_OP_KIND_AND
    assert e.bin.lhs.bin.op == ir_pb2.BIN_OP_KIND_SHR


def test_unresolved_ref_raises_at_serialization() -> None:
    f = FieldSpec(width_bits=4, display_name="X")  # no name/header yet
    expr = f * 4
    try:
        expr.to_pb()
    except RuntimeError as e:
        assert "finalized" in str(e)
    else:
        raise AssertionError("expected RuntimeError")
