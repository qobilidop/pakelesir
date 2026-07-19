#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t pakeles-dev .devcontainer >/dev/null
exec docker run --rm \
  -v "$PWD":/work -w /work \
  -v pakeles-target:/target \
  -v pakeles-cargo:/usr/local/cargo/registry \
  pakeles-dev "$@"
