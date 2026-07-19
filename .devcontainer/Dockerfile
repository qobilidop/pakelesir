# Dev environment from a plain Ubuntu base: everything installed
# explicitly, the same way you would on a real Linux machine.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential git \
      protobuf-compiler tshark graphviz \
      libz3-dev libclang-dev clang llvm \
 && rm -rf /var/lib/apt/lists/*

# buf CLI (pinned)
ARG BUF_VERSION=1.47.2
RUN curl -fsSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf

# p4c + behavioral-model (BMv2), built from pinned sources: no packages
# exist for Ubuntu 24.04 (p4lang OBS stops at 23.04; checked 2026-07-19 —
# revisit apt the day p4lang publishes noble packages). Thrift is required:
# bmv2's switch targets (simple_switch) only build with it. Nanomsg and
# logging macros stay off (we program no tables at runtime).
ARG BMV2_VERSION=1.15.4
ARG P4C_VERSION=1.2.5.15
RUN apt-get update && apt-get install -y --no-install-recommends \
      cmake g++ automake autoconf libtool pkg-config flex bison \
      libgc-dev libfl-dev libgmp-dev libpcap-dev libjudy-dev \
      libevent-dev libssl-dev libxxhash-dev libjsoncpp-dev \
      libthrift-dev thrift-compiler \
      libboost-dev libboost-graph-dev libboost-iostreams-dev \
      libboost-program-options-dev libboost-system-dev \
      libboost-filesystem-dev libboost-thread-dev \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://github.com/p4lang/behavioral-model/archive/refs/tags/${BMV2_VERSION}.tar.gz" | tar xz -C /tmp \
 && cd "/tmp/behavioral-model-${BMV2_VERSION}" \
 && ./autogen.sh \
 && ./configure --without-nanomsg --disable-logging-macros \
 && make -j"$(nproc)" && make install && ldconfig \
 && rm -rf "/tmp/behavioral-model-${BMV2_VERSION}"
# p4c's build additionally needs a python3 interpreter (IR generators).
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "v${P4C_VERSION}" --recursive \
      https://github.com/p4lang/p4c /tmp/p4c \
 && cmake -S /tmp/p4c -B /tmp/p4c/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_BMV2=ON -DENABLE_P4TEST=ON \
      -DENABLE_EBPF=OFF -DENABLE_UBPF=OFF -DENABLE_DPDK=OFF \
      -DENABLE_P4TC=OFF -DENABLE_P4FMT=OFF -DENABLE_DOCS=OFF \
      -DENABLE_GTESTS=OFF \
 && cmake --build /tmp/p4c/build -j"$(nproc)" \
 && cmake --install /tmp/p4c/build \
 && rm -rf /tmp/p4c

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
