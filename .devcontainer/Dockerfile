FROM rust:1-bookworm

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      protobuf-compiler tshark graphviz \
 && rm -rf /var/lib/apt/lists/*

ARG BUF_VERSION=1.47.2
RUN curl -fsSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf

ENV PROTOC=/usr/bin/protoc CARGO_TARGET_DIR=/target
