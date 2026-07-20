#!/usr/bin/env bash
# Regenerate the eth_ipvx_l4 gallery from its single source of truth,
# the Python eDSL. Run inside the dev image: ./dev.sh scripts/gen-examples.sh
set -euo pipefail
cd "$(dirname "$0")/.."

ir="examples/eth_ipvx_l4/eth_ipvx_l4.ir.json"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Phase 1: eDSL -> rough protojson -> Rust-canonical ir.json.
PYTHONPATH=py/src python3 -m pakeles.examples.eth_ipvx_l4 > "$tmp"
cargo run --quiet --bin pakeles -- fmt-ir --ir "$tmp" --out "$ir"

# Phase 2: derive gen/* + conformance/* + .py mirror from the canonical IR.
cargo run --quiet --bin gen_fixtures
cargo run --quiet --bin gen_examples

echo "gallery regenerated from py/src/pakeles/examples/eth_ipvx_l4.py"
