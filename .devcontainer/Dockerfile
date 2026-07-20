# Dev environment from a plain Ubuntu base: everything installed
# explicitly, the same way you would on a real Linux machine.
#
# Exception: p4c + BMv2 come prebuilt from qobilidop/p4lang-builds
# (personal multi-arch images with immutable version tags; recipes in
# that repo). No packages exist for Ubuntu 24.04 and a source build
# costs ~50 minutes per cold start.
ARG P4C_VERSION=1.2.5.15
ARG BMV2_VERSION=1.15.4
FROM ghcr.io/qobilidop/p4lang-builds/p4c:${P4C_VERSION}-noble AS p4c
FROM ghcr.io/qobilidop/p4lang-builds/bmv2:${BMV2_VERSION}-noble AS bmv2

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential git \
      protobuf-compiler tshark graphviz \
      libz3-dev libclang-dev clang llvm libbpf-dev \
 && rm -rf /var/lib/apt/lists/*

# buf CLI (pinned)
ARG BUF_VERSION=1.47.2
RUN curl -fsSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf

# p4c + BMv2, grafted from the prebuilt images pinned above (both are
# noble-based, so /usr/local grafts cleanly). The apt line installs the
# union of the runtime deps listed in each image's final stage (-dev
# packages for simplicity: they pull the runtime libs; the headers cost
# size, not correctness). cpp — p4c's runtime preprocessor — is already
# present via build-essential; python3 serves p4c's helper scripts.
COPY --from=p4c /usr/local /usr/local
COPY --from=bmv2 /usr/local /usr/local
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      libboost-iostreams-dev libboost-graph-dev libgc-dev libfl-dev \
      libgmp-dev libpcap-dev libjudy-dev libevent-dev libssl-dev \
      libxxhash-dev libjsoncpp-dev libthrift-dev \
      libboost-program-options-dev libboost-system-dev \
      libboost-filesystem-dev libboost-thread-dev \
 && rm -rf /var/lib/apt/lists/* \
 && ldconfig \
 && p4test --version \
 && p4c-bm2-ss --version \
 && simple_switch --help >/dev/null 2>&1

# Python authoring-surface tooling (slice 6). Pinned loosely; the gate
# (ruff/pyright/pytest) is what actually defines correctness.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --break-system-packages --no-cache-dir \
      "protobuf>=5" "pytest>=8" "ruff>=0.5" "pyright>=1.1.380"

# Rust via rustup, default profile (includes rustfmt + clippy).
# System-wide homes so dev.sh cache volumes can mount over them.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    PROTOC=/usr/bin/protoc \
    CARGO_TARGET_DIR=/target
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile default \
      --default-toolchain stable --no-modify-path
