"""The load-bearing test: the eDSL re-authors the gallery description
and must produce IR proto-equal to the committed `ir.json` the Rust
builder generated — two authoring surfaces, one artifact."""

import os
import subprocess
import sys
from pathlib import Path

from google.protobuf import json_format

from pakeles._pb import ir_pb2
from pakeles.examples.eth_ipvx_l4 import eth_ipvx_l4

GALLERY = Path(__file__).resolve().parents[2] / "examples/eth_ipvx_l4/eth_ipvx_l4.ir.json"
SRC = Path(__file__).resolve().parents[1] / "src"


def test_python_authoring_matches_gallery() -> None:
    ours = eth_ipvx_l4().to_pb()
    committed = json_format.Parse(GALLERY.read_text(), ir_pb2.Ir())
    assert ours == committed


def test_own_json_roundtrips_to_same_proto() -> None:
    p = eth_ipvx_l4()
    assert json_format.Parse(p.to_json(), ir_pb2.Ir()) == p.to_pb()


def test_module_main_emits_parseable_json() -> None:
    out = subprocess.run(
        [sys.executable, "-m", "pakeles.examples.eth_ipvx_l4"],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    ).stdout
    assert json_format.Parse(out, ir_pb2.Ir()) == eth_ipvx_l4().to_pb()
