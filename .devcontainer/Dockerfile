# Dev environment from a plain Ubuntu base: everything installed
# explicitly, the same way you would on a real Linux machine.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential git \
      protobuf-compiler tshark graphviz \
      libz3-dev libclang-dev \
 && rm -rf /var/lib/apt/lists/*

# buf CLI (pinned)
ARG BUF_VERSION=1.47.2
RUN curl -fsSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf

# Rust via rustup, default profile (includes rustfmt + clippy).
# System-wide homes so dev.sh cache volumes can mount over them.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    PROTOC=/usr/bin/protoc \
    CARGO_TARGET_DIR=/target
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile default \
      --default-toolchain stable --no-modify-path
