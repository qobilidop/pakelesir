# Slice 5 "the switch" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `gen p4` emits a P4-16/v1model program from the IR; `diff bmv2` verdict-compares the byte-aligned conformance vectors between the reference interpreter and BMv2 `simple_switch`.

**Architecture:** New backend `src/codegen/p4.rs` (mirrors `c.rs` structure: pure text emission from `pb::Ir`, unit-tested without tools, conformance-tested behind skip-if-missing guards). New oracle `src/oracle/bmv2.rs` (compile via `p4c-bm2-ss`, execute via `simple_switch --use-files` — pcap-file I/O, no veth/privileges). CLI gains `gen p4` and `diff bmv2`. Dev image gains pinned source-built p4c + behavioral-model.

**Tech Stack:** Rust (existing crate), P4-16 v1model, p4c (`p4c-bm2-ss`, `p4test`), BMv2 `simple_switch`, existing `pcapio`/`testvec`/`interp` modules.

## Global Constraints

- All dev/test runs go through `./dev.sh` (host has no toolchain).
- Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint` — green before every commit.
- Conformance tests skip cleanly when a tool is missing (pattern: `c.rs` `cc`/`clang` checks) so `cargo test` passes on images without the P4 toolchain.
- Spec: `docs/superpowers/specs/2026-07-19-slice5-design.md`. Semantic decisions (verdict encoding, error mapping, DAG-only, byte-aligned subset) live there and are not re-decided in tasks.
- Vectors file: `examples/eth_ipv4_tcp/vectors.json` (use the exact path the existing C conformance test reads).
- Work on branch `slice5-switch`; merge to main with a merge commit at the end.

---

### Task 1: P4 toolchain in the dev image

**Files:**
- Modify: `.devcontainer/Dockerfile` (append after the buf block, before the Rust block)
- Modify: `.github/workflows/ci.yml` (timeout 30 → 60)

**Interfaces:**
- Produces: `p4c-bm2-ss`, `p4test`, `simple_switch` on PATH inside the dev container. All later conformance tasks consume these.

- [ ] **Step 1: Append the toolchain block to `.devcontainer/Dockerfile`**

```dockerfile
# p4c + behavioral-model (BMv2), built from pinned sources: no packages
# exist for Ubuntu 24.04 (p4lang OBS stops at 23.04; checked 2026-07-19).
ARG BMV2_VERSION=1.15.0
ARG P4C_VERSION=1.2.4.14
RUN apt-get update && apt-get install -y --no-install-recommends \
      cmake g++ automake autoconf libtool pkg-config flex bison \
      libgc-dev libfl-dev libgmp-dev libpcap-dev libjudy-dev \
      libevent-dev libssl-dev \
      libboost-dev libboost-graph-dev libboost-iostreams-dev \
      libboost-program-options-dev libboost-system-dev \
      libboost-filesystem-dev libboost-thread-dev \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://github.com/p4lang/behavioral-model/archive/refs/tags/${BMV2_VERSION}.tar.gz" | tar xz \
 && cd "behavioral-model-${BMV2_VERSION}" \
 && ./autogen.sh \
 && ./configure --without-nanomsg --without-thrift --disable-logging-macros \
 && make -j"$(nproc)" && make install && ldconfig \
 && cd .. && rm -rf "behavioral-model-${BMV2_VERSION}"
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
```

Version pins are best-effort guesses at latest stable; **verify the tags exist** (`git ls-remote --tags https://github.com/p4lang/p4c "v1.2.4.*"`) and bump to the newest patch release before building. If p4c's CMake errors on missing protobuf, it FetchContents its own by default — do NOT add a system protobuf; if a flag is needed it is `-DP4C_USE_PREINSTALLED_PROTOBUF=OFF`.

- [ ] **Step 2: Build the image and fix what breaks**

Run: `./dev.sh true` (triggers the image build; expect 20–60 min cold)
Expected: build completes. Known likely adjustments: gcc-13 warnings-as-errors in bmv2 (`./configure CXXFLAGS="-Wno-error"` if needed); p4c missing dep (add the named `-dev` package to the apt line). Iterate until the build succeeds; keep the block minimal.

- [ ] **Step 3: Verify the three binaries**

Run: `./dev.sh sh -c 'p4test --version && p4c-bm2-ss --version && simple_switch --help | head -3'`
Expected: three version/usage outputs, no missing-library errors.

- [ ] **Step 4: Bump CI timeout**

In `.github/workflows/ci.yml` change `timeout-minutes: 30` to `timeout-minutes: 60` (cold image build now dominates; warm runs stay fast via the gha layer cache).

- [ ] **Step 5: Commit**

```bash
git add .devcontainer/Dockerfile .github/workflows/ci.yml
git commit -m "build: source-built p4c + bmv2 in dev image"
```

---

### Task 2: Emitter foundations — segmentation and varbit bounds

**Files:**
- Create: `src/codegen/p4.rs`
- Modify: `src/codegen/mod.rs` (add `pub mod p4;`)

**Interfaces:**
- Consumes: `pb::Ir`, `pb::HeaderType`, `pb::Expr` from `crate::ir::pb`.
- Produces (used by Tasks 3–6):
  - `pub(crate) enum Seg<'a> { Fixed(Vec<&'a pb::Field>), Var(&'a pb::Field) }`
  - `pub(crate) fn segments(ht: &pb::HeaderType) -> Vec<Seg<'_>>`
  - `pub(crate) fn expr_max(e: &pb::Expr, parser: &pb::Parser) -> Result<u128>` (max value of a length expr in bytes, by interval arithmetic)
  - `pub(crate) fn instance_order(parser: &pb::Parser) -> Vec<(String, String)>` (instance name → header type, in first-extract order; this order defines verdict bitmap bits, LSB first)

- [ ] **Step 1: Write the failing tests** (in `src/codegen/p4.rs` with a `#[cfg(test)] mod tests`)

```rust
#[test]
fn ipv4_splits_into_fixed_then_var() {
    let ir = crate::examples::eth_ipv4_tcp();
    let ipv4 = ir.parser.as_ref().unwrap().header_types.iter()
        .find(|h| h.name == "ipv4").unwrap();
    let segs = segments(ipv4);
    assert_eq!(segs.len(), 2);
    assert!(matches!(&segs[0], Seg::Fixed(fs) if fs.len() == 13));
    assert!(matches!(&segs[1], Seg::Var(f) if f.name == "options"));
}

#[test]
fn ipv4_options_max_is_40_bytes() {
    let ir = crate::examples::eth_ipv4_tcp();
    let parser = ir.parser.as_ref().unwrap();
    let ipv4 = parser.header_types.iter().find(|h| h.name == "ipv4").unwrap();
    let Seg::Var(f) = &segments(ipv4)[1] else { panic!() };
    let expr = match f.width.as_ref().unwrap().width.as_ref().unwrap() {
        pb::field_width::Width::ByteLen(e) => e,
        _ => panic!(),
    };
    assert_eq!(expr_max(expr, parser).unwrap(), 40); // (15*4)-20
}

#[test]
fn instance_order_is_extraction_order() {
    let ir = crate::examples::eth_ipv4_tcp();
    let order = instance_order(ir.parser.as_ref().unwrap());
    let names: Vec<&str> = order.iter().map(|(i, _)| i.as_str()).collect();
    assert_eq!(names, ["ethernet", "ipv4", "tcp"]);
}
```

- [ ] **Step 2: Run tests, verify they fail** — `./dev.sh cargo test codegen::p4` — expect compile errors (module empty).

- [ ] **Step 3: Implement**

```rust
//! P4-16 (v1model) backend: emit a BMv2-runnable program from the IR.

use crate::ir::pb;
use anyhow::{bail, Context, Result};

pub(crate) enum Seg<'a> {
    Fixed(Vec<&'a pb::Field>),
    Var(&'a pb::Field),
}

/// Split a header type at var-field boundaries: P4 requires a varbit to
/// terminate its header, so each var field becomes a companion header.
pub(crate) fn segments(ht: &pb::HeaderType) -> Vec<Seg<'_>> {
    let mut out = Vec::new();
    let mut run: Vec<&pb::Field> = Vec::new();
    for f in &ht.fields {
        match f.width.as_ref().and_then(|w| w.width.as_ref()) {
            Some(pb::field_width::Width::Bits(_)) => run.push(f),
            Some(pb::field_width::Width::ByteLen(_)) => {
                if !run.is_empty() {
                    out.push(Seg::Fixed(std::mem::take(&mut run)));
                }
                out.push(Seg::Var(f));
            }
            None => {}
        }
    }
    if !run.is_empty() {
        out.push(Seg::Fixed(run));
    }
    out
}

fn field_bits(parser: &pb::Parser, fr: &pb::FieldRef) -> Result<u32> {
    let ht_name = instance_order(parser)
        .into_iter()
        .find(|(i, _)| *i == fr.header)
        .map(|(_, t)| t)
        .with_context(|| format!("unknown instance {}", fr.header))?;
    let ht = parser.header_types.iter().find(|h| h.name == ht_name)
        .with_context(|| format!("unknown header type {ht_name}"))?;
    let f = ht.fields.iter().find(|f| f.name == fr.field)
        .with_context(|| format!("unknown field {}.{}", fr.header, fr.field))?;
    match f.width.as_ref().and_then(|w| w.width.as_ref()) {
        Some(pb::field_width::Width::Bits(b)) => Ok(*b),
        _ => bail!("length expr references non-fixed field {}.{}", fr.header, fr.field),
    }
}

/// Upper bound (bytes) of a length expression by interval arithmetic.
/// Sound, not tight: SUB/SHR assume rhs = 0; AND ≤ min; OR ≤ sum.
pub(crate) fn expr_max(e: &pb::Expr, parser: &pb::Parser) -> Result<u128> {
    Ok(match e.kind.as_ref().context("empty expr")? {
        pb::expr::Kind::Constant(c) => *c as u128,
        pb::expr::Kind::Field(fr) => (1u128 << field_bits(parser, fr)?) - 1,
        pb::expr::Kind::Bin(b) => {
            let l = expr_max(b.lhs.as_ref().context("no lhs")?, parser)?;
            let r = expr_max(b.rhs.as_ref().context("no rhs")?, parser)?;
            match b.op() {
                pb::BinOpKind::Add => l + r,
                pb::BinOpKind::Sub => l,
                pb::BinOpKind::Mul => l * r,
                pb::BinOpKind::Shl => l.checked_shl(r.min(64) as u32).context("shl overflow")?,
                pb::BinOpKind::Shr => l,
                pb::BinOpKind::And => l.min(r),
                pb::BinOpKind::Or => l + r,
                pb::BinOpKind::Unspecified => bail!("unspecified binop"),
            }
        }
    })
}

/// Header instances in first-extract order (bitmap bit order, LSB first).
pub(crate) fn instance_order(parser: &pb::Parser) -> Vec<(String, String)> {
    let mut seen = Vec::new();
    for s in &parser.states {
        for e in &s.extracts {
            let inst = if e.instance.is_empty() { &e.header_type } else { &e.instance };
            if !seen.iter().any(|(i, _): &(String, String)| i == inst) {
                seen.push((inst.clone(), e.header_type.clone()));
            }
        }
    }
    seen
}
```

Adjust `pb::` paths to the actual generated names (check `src/ir/mod.rs` re-exports and how `c.rs` matches on `field_width::Width` — copy its idiom exactly).

- [ ] **Step 4: Run tests, verify pass** — `./dev.sh cargo test codegen::p4` — 3 pass.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: p4 backend foundations (segmentation, varbit bounds)"`

---

### Task 3: Full P4 program emission

**Files:**
- Modify: `src/codegen/p4.rs`

**Interfaces:**
- Produces: `pub fn generate_p4(ir: &pb::Ir) -> Result<String>` — the complete v1model program. Task 4's CLI and Task 6's oracle consume it.
- Verdict contract (consumed by Task 6): output header `verdict_t { bit<8> bitmap; bit<8> err; }`; bitmap bit *i* (LSB first) = instance *i* of `instance_order` fully extracted (final segment `isValid()`); `err` codes: NoError=0, PacketTooShort=1, NoMatch=2, StackOutOfBounds=3, HeaderTooShort=4, ParserTimeout=5, ParserInvalidArgument=6, other=255.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn generated_p4_contains_expected_decls() {
    let p4 = generate_p4(&crate::examples::eth_ipv4_tcp()).unwrap();
    for needle in [
        "#include <v1model.p4>",
        "header ethernet_s0_t",
        "bit<48> dst;",
        "varbit<320> options;",
        "state st_parse_ipv4",
        "pkt.extract(hdr.ipv4_s0);",
        "transition select(",
        "16w0x800: st_parse_ipv4;",
        "default: reject;",
        "header verdict_t",
        "V1Switch(",
    ] {
        assert!(p4.contains(needle), "missing: {needle}\n---\n{p4}");
    }
}

#[test]
fn cyclic_graph_is_rejected() {
    let mut ir = crate::examples::eth_ipv4_tcp();
    // point tcp's accept back at parse_ethernet to force a cycle
    let p = ir.parser.as_mut().unwrap();
    let tcp = p.states.iter_mut().find(|s| s.name == "parse_tcp").unwrap();
    tcp.transition = Some(pb::Transition {
        kind: Some(pb::transition::Kind::Direct(pb::Target {
            kind: Some(pb::target::Kind::State("parse_ethernet".into())),
        })),
    });
    assert!(generate_p4(&ir).is_err());
}
```

- [ ] **Step 2: Run, verify fail** — `generate_p4` undefined.

- [ ] **Step 3: Implement `generate_p4`**

Emission order: prologue, per-segment header decls, `verdict_t`, `struct headers` / `struct metadata`, parser, checksum stubs, ingress (bitmap + error if-chain + `egress_spec = 1`), empty egress, deparser (emit verdict only), `V1Switch` package line. Core skeleton:

```rust
fn seg_type_name(inst: &str, i: usize, seg: &Seg) -> String {
    match seg {
        Seg::Fixed(_) => format!("{inst}_s{i}_t"),
        Seg::Var(_) => format!("{inst}_v{i}_t"),
    }
}
fn seg_member_name(inst: &str, i: usize, seg: &Seg) -> String {
    match seg {
        Seg::Fixed(_) => format!("{inst}_s{i}"),
        Seg::Var(_) => format!("{inst}_v{i}"),
    }
}

fn expr_p4(e: &pb::Expr, parser: &pb::Parser) -> Result<String> {
    Ok(match e.kind.as_ref().context("empty expr")? {
        pb::expr::Kind::Constant(c) => format!("32w{c}"),
        pb::expr::Kind::Field(fr) => {
            let member = member_of_field(parser, fr)?; // find segment holding fr.field
            format!("(bit<32>)hdr.{member}.{}", fr.field)
        }
        pb::expr::Kind::Bin(b) => {
            let op = match b.op() {
                pb::BinOpKind::Add => "+", pb::BinOpKind::Sub => "-",
                pb::BinOpKind::Mul => "*", pb::BinOpKind::Shl => "<<",
                pb::BinOpKind::Shr => ">>", pb::BinOpKind::And => "&",
                pb::BinOpKind::Or => "|",
                pb::BinOpKind::Unspecified => bail!("unspecified binop"),
            };
            format!("({} {} {})",
                expr_p4(b.lhs.as_ref().unwrap(), parser)?, op,
                expr_p4(b.rhs.as_ref().unwrap(), parser)?)
        }
    })
}
```

Parser states: P4 entry state must be `start` → emit `state start { transition st_<start_state>; }` and prefix every IR state `st_`. Per state: one `pkt.extract(hdr.<seg>)` per fixed segment, `pkt.extract(hdr.<var seg>, (bit<32>)(8 * <expr_p4>))` per var segment, then the transition. Keyset entries: value → `<W>w<val>` sized by the key's field width (`16w0x800`), masked → `val &&& mask`, range → `lo .. hi`; tuple keys parenthesized. `Target` → `st_<name>` / `accept` / `reject`. Cycle detection: DFS over state→target edges before emitting; `bail!` on a back edge (spec: DAG only until the TLV slice). Bitmap: `bail!` if `instance_order` has more than 8 instances.

Error if-chain in ingress (P4 `error` is not bit-castable):

```p4
bit<8> err = 8w255;
if (smeta.parser_error == error.NoError) { err = 8w0; }
else if (smeta.parser_error == error.PacketTooShort) { err = 8w1; }
else if (smeta.parser_error == error.NoMatch) { err = 8w2; }
else if (smeta.parser_error == error.StackOutOfBounds) { err = 8w3; }
else if (smeta.parser_error == error.HeaderTooShort) { err = 8w4; }
else if (smeta.parser_error == error.ParserTimeout) { err = 8w5; }
else if (smeta.parser_error == error.ParserInvalidArgument) { err = 8w6; }
```

- [ ] **Step 4: Run tests, verify pass** — `./dev.sh cargo test codegen::p4`

- [ ] **Step 5: Add the p4test compile test (skip-if-missing)**

```rust
#[test]
fn generated_p4_compiles_with_p4test() {
    if std::process::Command::new("p4test").arg("--version").output().is_err() {
        eprintln!("skipping: p4test not available");
        return;
    }
    let p4 = generate_p4(&crate::examples::eth_ipv4_tcp()).unwrap();
    let dir = std::env::temp_dir().join("pakeles_p4test");
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("parser.p4");
    std::fs::write(&src, &p4).unwrap();
    let out = std::process::Command::new("p4test").arg(&src).output().unwrap();
    assert!(out.status.success(), "p4test rejected:\n{}",
        String::from_utf8_lossy(&out.stderr));
    assert!(out.stderr.is_empty(), "p4test warnings:\n{}",
        String::from_utf8_lossy(&out.stderr));
}
```

- [ ] **Step 6: Run inside the container; iterate the emitter until p4test is clean** — `./dev.sh cargo test codegen::p4` — expect several rounds (casts, sized literals, varbit extract signature). p4c error messages name the line; fix emission, not the test.

- [ ] **Step 7: Commit** — `git commit -am "feat: gen p4 — full v1model program, p4test-clean"`

---

### Task 4: CLI verb + gallery artifact

**Files:**
- Modify: `src/cli.rs` (new `GenTarget::P4` variant + dispatch arm, mirroring `Lua`)
- Modify: `src/bin/gen_examples.rs` (also write `examples/eth_ipv4_tcp/parser.p4`)
- Create: `examples/eth_ipv4_tcp/parser.p4` (generated)

**Interfaces:**
- Consumes: `codegen::p4::generate_p4`.
- Produces: `pakeles gen p4 [--ir X] [--out Y]`; committed gallery artifact.

- [ ] **Step 1: Failing test** (in `src/codegen/p4.rs` tests, mirroring `committed_c_artifacts_current`)

```rust
#[test]
fn committed_p4_artifact_current() {
    let p4 = generate_p4(&crate::examples::eth_ipv4_tcp()).unwrap();
    let committed = std::fs::read_to_string("examples/eth_ipv4_tcp/parser.p4").unwrap();
    assert_eq!(p4, committed,
        "examples/ drifted; regenerate: ./dev.sh cargo run --bin gen_examples");
}
```

- [ ] **Step 2: Run, verify fail** — file missing.

- [ ] **Step 3: Implement** — `GenTarget::P4 { ir: Option<PathBuf>, out: PathBuf }` with the exact shape of `GenTarget::Lua`; extend `gen_examples.rs` following how it writes `dissector.lua`. Run `./dev.sh cargo run --bin gen_examples` to produce the artifact.

- [ ] **Step 4: Run tests** — `./dev.sh cargo test` — all pass, incl. the new guard.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: gen p4 CLI verb + gallery parser.p4"`

---

### Task 5: BMv2 runner

**Files:**
- Create: `src/oracle/bmv2.rs`
- Modify: `src/oracle/mod.rs` (add `pub mod bmv2;`)

**Interfaces:**
- Produces (Task 6 consumes):
  - `pub struct Verdict { pub delivered: bool, pub bitmap: u8, pub err: u8 }`
  - `pub fn compile(p4_src: &str, workdir: &Path) -> Result<PathBuf>` — writes `prog.p4`, runs `p4c-bm2-ss prog.p4 -o prog.json`, returns json path.
  - `pub fn run_one(json: &Path, packet: &[u8], workdir: &Path) -> Result<Verdict>`
  - `pub fn tools_available() -> bool` — both `p4c-bm2-ss` and `simple_switch` respond.

- [ ] **Step 1: Failing test**

```rust
#[test]
fn accept_vector_roundtrips_through_bmv2() {
    if !tools_available() {
        eprintln!("skipping: p4 toolchain not available");
        return;
    }
    let ir = crate::examples::eth_ipv4_tcp();
    let p4 = crate::codegen::p4::generate_p4(&ir).unwrap();
    let dir = std::env::temp_dir().join("pakeles_bmv2_unit");
    std::fs::create_dir_all(&dir).unwrap();
    let json = compile(&p4, &dir).unwrap();
    // minimal accept packet: eth(type=0x0800) + ipv4(ihl=5, proto=6) + tcp
    let suite = crate::testvec::suite_from_json(
        &std::fs::read_to_string("examples/eth_ipv4_tcp/vectors.json").unwrap()).unwrap();
    let (packets, _) = crate::testvec::suite_to_packets(&suite);
    let v = run_one(&json, &packets[0], &dir).unwrap();
    assert!(v.delivered);
}
```

- [ ] **Step 2: Run, verify fail** — module undefined.

- [ ] **Step 3: Implement**

```rust
//! BMv2 differential oracle: run packets through simple_switch.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct Verdict { pub delivered: bool, pub bitmap: u8, pub err: u8 }

pub fn tools_available() -> bool {
    Command::new("p4c-bm2-ss").arg("--version").output().is_ok()
        && Command::new("simple_switch").arg("--help").output().is_ok()
}

pub fn compile(p4_src: &str, workdir: &Path) -> Result<PathBuf> {
    let src = workdir.join("prog.p4");
    let json = workdir.join("prog.json");
    std::fs::write(&src, p4_src)?;
    let out = Command::new("p4c-bm2-ss").arg(&src).arg("-o").arg(&json)
        .output().context("running p4c-bm2-ss")?;
    if !out.status.success() {
        bail!("p4c-bm2-ss failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(json)
}

pub fn run_one(json: &Path, packet: &[u8], workdir: &Path) -> Result<Verdict> {
    // fresh subdir per invocation: simple_switch reads p0_in.pcap, writes p1_out.pcap
    let dir = workdir.join(format!("pkt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    crate::pcapio::write_pcap(&dir.join("p0_in.pcap"), &[packet.to_vec()])?;
    crate::pcapio::write_pcap(&dir.join("p1_in.pcap"), &[])?; // port 1 input must exist
    let mut child: Child = Command::new("simple_switch")
        .args(["--use-files", "0", "-i", "0@p0", "-i", "1@p1"])
        .arg(json.canonicalize()?)
        .current_dir(&dir)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().context("spawning simple_switch")?;
    // poll for an output packet; rejects (if BMv2 drops them) never produce one
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let out_pcap = dir.join("p1_out.pcap");
    let verdict = loop {
        if let Ok(pkts) = crate::pcapio::read_packets(&out_pcap) {
            if let Some(p) = pkts.first() {
                if p.len() < 2 { bail!("verdict frame too short: {} bytes", p.len()); }
                break Verdict { delivered: true, bitmap: p[0], err: p[1] };
            }
        }
        if std::time::Instant::now() > deadline {
            break Verdict { delivered: false, bitmap: 0, err: 0 };
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    Ok(verdict)
}
```

Expect iteration on `--use-files` mechanics (flag takes a wait-seconds argument; file naming is `<iface>_in.pcap`/`<iface>_out.pcap` relative to cwd). If output never appears for a known-good accept packet, run once with stderr visible to see BMv2's interface log lines and adjust names/flags.

- [ ] **Step 4: Run test** — `./dev.sh cargo test oracle::bmv2` — pass (delivered accept verdict).

- [ ] **Step 5: Commit** — `git commit -am "feat: bmv2 runner (compile + pcap-file execution)"`

---

### Task 6: `diff bmv2` + full conformance

**Files:**
- Modify: `src/oracle/bmv2.rs` (expected-verdict derivation + suite diff)
- Modify: `src/cli.rs` (new `Oracle::Bmv2` variant + dispatch)

**Interfaces:**
- Produces:
  - `pub fn expected(ir: &pb::Ir, bits: &crate::testvec::Bits) -> Result<Verdict>` — derived from `interp::run_bits` per the spec's mapping (never hardcoded).
  - `pub fn diff_suite(ir: &pb::Ir, suite: &pb::TestSuite) -> Result<DiffReport>` with `pub struct DiffReport { pub compared: usize, pub skipped_bit_granular: usize, pub mismatches: Vec<String> }`
  - CLI: `pakeles diff bmv2 [--ir X] [--vectors Y]`, exit 1 on mismatch.

- [ ] **Step 1: Failing test — the conformance test**

```rust
#[test]
fn bmv2_conformance_byte_aligned_suite() {
    if !tools_available() {
        eprintln!("skipping: p4 toolchain not available");
        return;
    }
    let ir = crate::examples::eth_ipv4_tcp();
    let suite = crate::testvec::suite_from_json(
        &std::fs::read_to_string("examples/eth_ipv4_tcp/vectors.json").unwrap()).unwrap();
    let report = diff_suite(&ir, &suite).unwrap();
    assert!(report.compared > 30, "suspiciously few byte-aligned vectors: {}", report.compared);
    assert!(report.mismatches.is_empty(), "mismatches:\n{}", report.mismatches.join("\n"));
}
```

- [ ] **Step 2: Run, verify fail** — functions undefined.

- [ ] **Step 3: Implement `expected`**

Mapping (from the spec): run `interp::run_bits`; bitmap = bit *i* set iff instance *i* of `codegen::p4::instance_order` appears fully in `ParseResult.headers` AND is not the truncation site (`error.instance` with `severity == Error` and a truncation reason — a partially-extracted instance is invalid in P4 because extracts are atomic). err = 1 (`PacketTooShort`) when the interp error is a truncation, else 0 (accepts and explicit rejects both reach ingress with `NoError`). `delivered` = true (v1model delivers parser-rejected packets to ingress; if Task 5's unit test proved otherwise for rejects, compare `delivered=false` for reject vectors instead and note it in the module doc — the spec documents this fallback).

Distinguish truncation from explicit reject the same way the vector suite does: check how `testvec`/`testgen` label reject vectors (truncation vectors carry the truncated field/bit offset) and follow the existing convention — do not invent a new signal.

- [ ] **Step 4: Implement `diff_suite`** — iterate `suite.vectors`, skip non-byte-aligned (`bit_len % 8 != 0`, count them), compile once, `run_one` per vector, compare against `expected`, collect mismatch strings `"vector {i} ({name}): expected bm={:08b} err={} got bm={:08b} err={}"`.

- [ ] **Step 5: CLI wiring** — `Oracle::Bmv2 { ir: Option<PathBuf>, vectors: Option<PathBuf> }` (vectors default `examples/eth_ipv4_tcp/vectors.json`); print `"{compared} vectors compared ({skipped} bit-granular skipped), {n} mismatches"` + lines; exit 1 on mismatches. Mirror the `Oracle::Tshark` arm.

- [ ] **Step 6: Run the conformance test; iterate to zero mismatches** — `./dev.sh cargo test bmv2_conformance -- --nocapture`. Debugging order when mismatching: (1) run the vector through `pakeles run` to see interp's view; (2) rerun `simple_switch` with `--log-console` on that packet to see BMv2's parse trace; (3) fix the *emitter* or the *expected-mapping*, never special-case a vector.

- [ ] **Step 7: Full gate** — `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint'`

- [ ] **Step 8: Commit** — `git commit -am "feat: diff bmv2 — verdict-level conformance vs simple_switch"`

---

### Task 7: Docs, gate, merge

**Files:**
- Modify: `README.md` (status paragraph: five agreeing implementations, gen p4 + diff bmv2 in the artifact list)
- Modify: `examples/eth_ipv4_tcp/README.md` (add parser.p4 row, if the file lists artifacts)

**Steps:**

- [ ] **Step 1: Update READMEs** — mention `parser.p4`, `gen p4`, `diff bmv2`, five provably-agreeing implementations (interp, Lua, C, eBPF, BMv2/P4).
- [ ] **Step 2: Full gate once more** — all green.
- [ ] **Step 3: Merge**

```bash
git checkout main && git merge --no-ff slice5-switch -m "Merge slice 5: the switch"
git push
```

- [ ] **Step 4: Watch CI** — first run rebuilds the image (~40–60 min); confirm green before starting slice 6.
