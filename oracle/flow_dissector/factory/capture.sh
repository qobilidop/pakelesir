#!/usr/bin/env bash
# Mint version-tagged golden flow_keys by running UPSTREAM bpf_flow.c
# (Linux v6.8 selftests, GPL-2.0 — fetched at capture time, NEVER
# committed; see the rung-1 design doc) in the kernel over corpus.txt.
# PRIVILEGED — run via:
#   ./dev-priv.sh oracle/flow_dissector/factory/capture.sh
set -euo pipefail
cd "$(dirname "$0")"

# --- pinned upstream source -------------------------------------------
KERNEL_TAG="v6.8"
BPF_FLOW_URL="https://raw.githubusercontent.com/torvalds/linux/${KERNEL_TAG}/tools/testing/selftests/bpf/progs/bpf_flow.c"
BPF_FLOW_SHA256="f01d08e66653fbaad811d289adea078c96a8511433ceaa3877b0eea6a208d41a"

mkdir -p build
if ! echo "${BPF_FLOW_SHA256}  build/bpf_flow.c" | sha256sum -c --status 2>/dev/null; then
  curl -fsSL "${BPF_FLOW_URL}" -o build/bpf_flow.c
  echo "${BPF_FLOW_SHA256}  build/bpf_flow.c" | sha256sum -c
fi

ver="$(uname -r)"
short="${ver%%-*}"
out="../../../examples/linux_flow_dissector/conformance/flow_keys.linux-${short}.golden.json"
mkdir -p "$(dirname "$out")"

# -I the multiarch dir so <asm/types.h> resolves under -target bpf (works
# on both arm64 devcontainer and x86_64 CI runners).
clang -O2 -g -target bpf -I"/usr/include/$(uname -m)-linux-gnu" \
  -c build/bpf_flow.c -o build/bpf_flow.o
cc -O2 -o build/capture capture.c -lbpf
build/capture build/bpf_flow.o corpus.txt > "$out"

echo "captured goldens from upstream bpf_flow.c@${KERNEL_TAG} on kernel ${ver} -> ${out}"
