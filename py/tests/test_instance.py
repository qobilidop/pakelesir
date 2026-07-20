"""Named header instances: `VLAN["vlan_q"]` extracts a second copy of a
header type and yields instance-bound field references."""

import pytest
from google.protobuf import json_format

from pakeles import Header, bits, extract, parser, reject
from pakeles._pb import ir_pb2


class Tag(Header):
    vid = bits(12)
    pad = bits(4)
    proto = bits(16)


class Eth(Header):
    ethertype = bits(16)


def two_tag_parser():
    return parser(
        "two_tags",
        max_depth=3,
        start="s0",
        states={
            "s0": extract(Eth).select(
                Eth.ethertype, {0x8100: "s1"}, default=reject("no")
            ),
            "s1": extract(Tag["outer"]).select(
                Tag["outer"].proto, {0x8100: "s2"}, default=reject("no")
            ),
            "s2": extract(Tag["inner"]).accept(),
        },
    )


def test_extract_records_instance_name() -> None:
    ir = two_tag_parser().to_pb()
    states = {s.name: s for s in ir.parser.states}
    assert states["s1"].extracts[0].header_type == "tag"
    assert states["s1"].extracts[0].instance == "outer"
    assert states["s2"].extracts[0].instance == "inner"
    # Default-instance extraction stays empty (canonical form).
    assert states["s0"].extracts[0].instance == ""


def test_bound_field_ref_serializes_instance_name() -> None:
    ir = two_tag_parser().to_pb()
    states = {s.name: s for s in ir.parser.states}
    key = states["s1"].transition.select.keys[0]
    assert key.field.header == "outer"
    assert key.field.field == "proto"


def test_header_type_emitted_once_for_two_instances() -> None:
    ir = two_tag_parser().to_pb()
    assert [h.name for h in ir.parser.header_types].count("tag") == 1


def test_unknown_field_on_instance_raises() -> None:
    with pytest.raises(AttributeError):
        _ = Tag["outer"].nope  # type: ignore[attr-defined]


def test_bound_field_arm_width_check_still_applies() -> None:
    with pytest.raises(ValueError, match="does not fit"):
        parser(
            "bad",
            max_depth=2,
            start="s0",
            states={
                "s0": extract(Tag["t"]).select(
                    Tag["t"].vid, {1 << 12: "s0"}, default=reject("no")
                ),
            },
        )


def test_roundtrips_through_json() -> None:
    p = two_tag_parser()
    assert json_format.Parse(p.to_json(), ir_pb2.Ir()) == p.to_pb()
