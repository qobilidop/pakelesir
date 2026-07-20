#!/usr/bin/env bash
# Privileged variant of dev.sh, ONLY for the flow-dissector golden factory
# (needs bpf()/BPF_PROG_TEST_RUN, which the normal unprivileged container
# cannot call). Never used by the normal gate.
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t pakeles-dev .devcontainer >/dev/null
exec docker run --rm --privileged \
  -v "$PWD":/work -w /work \
  pakeles-dev "$@"
