#!/usr/bin/env bash
# Mint version-tagged golden flow_keys by running the in-repo flow
# dissector in the kernel over corpus.txt. PRIVILEGED — run via:
#   ./dev-priv.sh oracle/flow_dissector/factory/capture.sh
set -euo pipefail
cd "$(dirname "$0")"

ver="$(uname -r)"
short="${ver%%-*}"
out="../../../examples/linux_flow_dissector/conformance/flow_keys.linux-${short}.golden.json"
mkdir -p "$(dirname "$out")"

clang -O2 -target bpf -I/usr/include/aarch64-linux-gnu -c flow_dissector.bpf.c -o /tmp/fd.o
llvm-objcopy -O binary --only-section=.text /tmp/fd.o /tmp/fd.text
clang -O2 -o /tmp/capture capture.c
/tmp/capture /tmp/fd.text corpus.txt > "$out"

echo "captured goldens for kernel ${ver} -> ${out}"
