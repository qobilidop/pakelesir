"""The load-bearing test: the eDSL re-authors the gallery description
and must produce IR proto-equal to the committed `ir.json` the Rust
builder generated — two authoring surfaces, one artifact."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from google.protobuf import json_format

from pakeles._pb import ir_pb2
from pakeles.examples.eth_ipvx_l4 import eth_ipvx_l4
from pakeles.examples.linux_flow_dissector import linux_flow_dissector

ROOT = Path(__file__).resolve().parents[2]
SRC = Path(__file__).resolve().parents[1] / "src"

BUILDERS = {
    "eth_ipvx_l4": eth_ipvx_l4,
    "linux_flow_dissector": linux_flow_dissector,
}


@pytest.mark.parametrize("name", ["eth_ipvx_l4", "linux_flow_dissector"])
def test_python_authoring_matches_gallery(name: str) -> None:
    gallery = ROOT / f"examples/{name}/{name}.ir.json"
    ours = BUILDERS[name]().to_pb()
    committed = json_format.Parse(gallery.read_text(), ir_pb2.Ir())
    assert ours == committed


@pytest.mark.parametrize("name", ["eth_ipvx_l4", "linux_flow_dissector"])
def test_own_json_roundtrips_to_same_proto(name: str) -> None:
    p = BUILDERS[name]()
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
