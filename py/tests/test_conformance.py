"""The load-bearing test: the eDSL re-authors the gallery description
and must produce IR proto-equal to the committed `ir.json` the Rust
builder generated — two authoring surfaces, one artifact."""

from pathlib import Path

from google.protobuf import json_format

from pakeles._pb import ir_pb2
from pakeles.examples.eth_ipv4_tcp import eth_ipv4_tcp

GALLERY = Path(__file__).resolve().parents[2] / "examples/eth_ipv4_tcp/ir.json"


def test_python_authoring_matches_gallery() -> None:
    ours = eth_ipv4_tcp().to_pb()
    committed = json_format.Parse(GALLERY.read_text(), ir_pb2.Ir())
    assert ours == committed


def test_own_json_roundtrips_to_same_proto() -> None:
    p = eth_ipv4_tcp()
    assert json_format.Parse(p.to_json(), ir_pb2.Ir()) == p.to_pb()
