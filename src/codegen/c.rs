//! C99 emitter (portable datapath parser) and its eBPF variant.
//!
//! Both targets share one core shape: a single `parse` function built
//! as `for (depth) { switch (state) { ... } }` — no recursion, no
//! unbounded loops, no external calls. That is deliberately the shape
//! the kernel verifier wants, and it is equally clean as portable C.
//!
//! u64 wrapping arithmetic matches reference semantics natively.
//! Length feasibility uses division form to dodge u64 overflow on
//! wrapped lengths.

use crate::ir::pb;
use anyhow::{bail, Result};
use std::fmt::Write;

pub struct CArtifacts {
    pub header: String,
    pub source: String,
}

/// Reasons get stable codes: the three built-ins, then authored
/// reasons sorted. Returns (reason, code) pairs.
fn reason_table(parser: &pb::Parser) -> Vec<(String, u32)> {
    let mut authored = std::collections::BTreeSet::new();
    let mut visit_target = |t: &pb::Target| {
        if let Some(pb::target::Kind::Reject(r)) = &t.kind {
            authored.insert(r.reason.clone());
        }
    };
    for s in &parser.states {
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => visit_target(t),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    if let Some(t) = &arm.next {
                        visit_target(t);
                    }
                }
                if let Some(t) = &sel.default_target {
                    visit_target(t);
                }
            }
            None => {}
        }
    }
    let mut out = vec![
        ("out of bounds".to_string(), 1),
        ("max depth exceeded".to_string(), 2),
        ("no matching select arm".to_string(), 3),
    ];
    let mut next = 16u32;
    for r in authored {
        if out.iter().any(|(existing, _)| *existing == r) {
            continue;
        }
        out.push((r, next));
        next += 1;
    }
    out
}

fn reason_ident(reason: &str) -> String {
    let mut s = String::from("PK_R_");
    for ch in reason.chars() {
        s.push(if ch.is_ascii_alphanumeric() {
            ch.to_ascii_uppercase()
        } else {
            '_'
        });
    }
    s
}

fn uint_type(bits: u32) -> &'static str {
    match bits {
        1..=8 => "uint8_t",
        9..=16 => "uint16_t",
        17..=32 => "uint32_t",
        _ => "uint64_t",
    }
}

/// Header instances in extraction order: (instance, header type).
fn instances(parser: &pb::Parser) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for s in &parser.states {
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                ex.header_type.clone()
            } else {
                ex.instance.clone()
            };
            if !out.iter().any(|(i, _)| *i == inst) {
                out.push((inst, ex.header_type.clone()));
            }
        }
    }
    out
}

fn expr_c(e: &pb::Expr) -> Result<String> {
    match e.kind.as_ref() {
        Some(pb::expr::Kind::Constant(v)) => Ok(format!("{v}ULL")),
        Some(pb::expr::Kind::Field(r)) => Ok(format!("(uint64_t)out->{}.{}", r.header, r.field)),
        Some(pb::expr::Kind::Bin(b)) => {
            let l = expr_c(
                b.lhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing lhs"))?,
            )?;
            let r = expr_c(
                b.rhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing rhs"))?,
            )?;
            let op = match pb::BinOpKind::try_from(b.op) {
                Ok(pb::BinOpKind::Add) => "+",
                Ok(pb::BinOpKind::Sub) => "-",
                Ok(pb::BinOpKind::Mul) => "*",
                Ok(pb::BinOpKind::Shl) => "<<",
                Ok(pb::BinOpKind::Shr) => ">>",
                Ok(pb::BinOpKind::And) => "&",
                Ok(pb::BinOpKind::Or) => "|",
                _ => bail!("unspecified binop"),
            };
            Ok(format!("({l} {op} {r})"))
        }
        None => bail!("empty expression"),
    }
}

fn entry_c(entry: &pb::KeysetEntry, key: &str) -> String {
    match entry.kind.as_ref() {
        Some(pb::keyset_entry::Kind::Value(v)) => format!("{key} == {v}ULL"),
        Some(pb::keyset_entry::Kind::Masked(m)) => {
            format!("({key} & {}ULL) == {}ULL", m.mask, m.value & m.mask)
        }
        Some(pb::keyset_entry::Kind::Range(r)) => {
            format!("({}ULL <= {key} && {key} <= {}ULL)", r.lo, r.hi)
        }
        None => "0".into(),
    }
}

struct Emit<'a> {
    parser: &'a pb::Parser,
    prefix: String,
    reasons: Vec<(String, u32)>,
}

impl<'a> Emit<'a> {
    fn new(parser: &'a pb::Parser) -> Self {
        Self {
            prefix: format!("pk_{}", parser.name),
            reasons: reason_table(parser),
            parser,
        }
    }

    fn structs(&self) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        for (inst, ht_name) in instances(self.parser) {
            let ht = self
                .parser
                .header_types
                .iter()
                .find(|h| h.name == ht_name)
                .ok_or_else(|| anyhow::anyhow!("unknown header type `{ht_name}`"))?;
            writeln!(w, "typedef struct {{")?;
            for f in &ht.fields {
                match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                    Some(pb::field_width::Width::Bits(n)) => {
                        writeln!(w, "  {} {};", uint_type(*n), f.name)?;
                    }
                    Some(pb::field_width::Width::ByteLen(_)) => {
                        writeln!(w, "  uint64_t {}_bit_off;", f.name)?;
                        writeln!(w, "  uint64_t {}_bit_len;", f.name)?;
                    }
                    None => bail!("field `{}` has no width", f.name),
                }
            }
            writeln!(w, "}} {p}_{inst}_t;")?;
            writeln!(w)?;
        }
        writeln!(w, "typedef struct {{")?;
        writeln!(w, "  uint8_t outcome; /* 0 = accept, 1 = reject */")?;
        writeln!(w, "  uint16_t reason; /* {p}_reason */")?;
        writeln!(w, "  uint64_t consumed_bits;")?;
        for (inst, _) in instances(self.parser) {
            writeln!(w, "  uint8_t {inst}_present;")?;
            writeln!(w, "  {p}_{inst}_t {inst};")?;
        }
        writeln!(w, "}} {p}_result_t;")?;
        Ok(w)
    }

    fn header(&self) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        let guard = format!("{}_H", p.to_uppercase());
        writeln!(
            w,
            "/* Generated by pakeles from `{}`. Do not edit:",
            self.parser.name
        )?;
        writeln!(w, " * regenerate with `pakeles gen c`. */")?;
        writeln!(w, "#ifndef {guard}")?;
        writeln!(w, "#define {guard}")?;
        writeln!(w)?;
        writeln!(w, "#include <stdint.h>")?;
        writeln!(w, "#include <stddef.h>")?;
        writeln!(w)?;
        writeln!(
            w,
            "enum {{ {}_ACCEPT = 0, {}_REJECT = 1 }};",
            p.to_uppercase(),
            p.to_uppercase()
        )?;
        writeln!(w)?;
        writeln!(w, "typedef enum {{")?;
        writeln!(w, "  PK_R_NONE = 0,")?;
        for (reason, code) in &self.reasons {
            writeln!(w, "  {} = {code}, /* \"{reason}\" */", reason_ident(reason))?;
        }
        writeln!(w, "}} {p}_reason_t;")?;
        writeln!(w)?;
        w.push_str(&self.structs()?);
        writeln!(w)?;
        writeln!(
            w,
            "/* Parse `bit_len` bits of `buf` (reject mode). Returns outcome. */"
        )?;
        writeln!(
            w,
            "int {p}_parse(const uint8_t *buf, uint64_t bit_len, {p}_result_t *out);"
        )?;
        writeln!(w, "const char *{p}_reason_str(uint16_t reason);")?;
        writeln!(w)?;
        writeln!(w, "#endif /* {guard} */")?;
        Ok(w)
    }

    /// The parse core: shared verbatim between portable C and eBPF.
    fn core(&self, static_qual: &str) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        writeln!(
            w,
            "{static_qual} uint64_t pk_read_bits(const uint8_t *buf, uint64_t off, uint32_t n) {{"
        )?;
        writeln!(w, "  uint64_t v = 0;")?;
        writeln!(w, "  uint32_t i;")?;
        writeln!(w, "  for (i = 0; i < n; i++) {{")?;
        writeln!(w, "    uint64_t pos = off + i;")?;
        writeln!(
            w,
            "    v = (v << 1) | (uint64_t)((buf[pos >> 3] >> (7 - (pos & 7))) & 1);"
        )?;
        writeln!(w, "  }}")?;
        writeln!(w, "  return v;")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        // State ids.
        for (i, s) in self.parser.states.iter().enumerate() {
            writeln!(w, "#define PK_S_{} {i}", s.name.to_uppercase())?;
        }
        writeln!(w)?;

        writeln!(
            w,
            "{static_qual} int {p}_parse_core(const uint8_t *buf, uint64_t bit_len, {p}_result_t *out) {{"
        )?;
        writeln!(w, "  uint64_t off = 0;")?;
        writeln!(
            w,
            "  uint32_t state = PK_S_{};",
            self.parser.start_state.to_uppercase()
        )?;
        writeln!(w, "  uint32_t depth;")?;
        writeln!(
            w,
            "  for (depth = 0; depth < {}u; depth++) {{",
            self.parser.max_depth
        )?;
        writeln!(w, "    switch (state) {{")?;
        for s in &self.parser.states {
            writeln!(w, "    case PK_S_{}: {{", s.name.to_uppercase())?;
            self.emit_state_body(&mut w, s)?;
            writeln!(w, "    }}")?;
        }
        writeln!(w, "    }}")?;
        writeln!(w, "  }}")?;
        writeln!(w, "  out->outcome = 1;")?;
        writeln!(w, "  out->reason = PK_R_MAX_DEPTH_EXCEEDED;")?;
        writeln!(w, "  out->consumed_bits = off;")?;
        writeln!(w, "  return 1;")?;
        writeln!(w, "}}")?;
        Ok(w)
    }

    fn emit_reject(&self, w: &mut String, indent: &str, reason: &str) -> Result<()> {
        writeln!(w, "{indent}out->outcome = 1;")?;
        writeln!(w, "{indent}out->reason = {};", reason_ident(reason))?;
        writeln!(w, "{indent}out->consumed_bits = off;")?;
        writeln!(w, "{indent}return 1;")?;
        Ok(())
    }

    fn emit_target(&self, w: &mut String, indent: &str, t: &pb::Target) -> Result<()> {
        match t.kind.as_ref() {
            Some(pb::target::Kind::State(name)) => {
                writeln!(w, "{indent}state = PK_S_{};", name.to_uppercase())?;
                writeln!(w, "{indent}continue;")?;
            }
            Some(pb::target::Kind::Accept(_)) => {
                writeln!(w, "{indent}out->outcome = 0;")?;
                writeln!(w, "{indent}out->reason = PK_R_NONE;")?;
                writeln!(w, "{indent}out->consumed_bits = off;")?;
                writeln!(w, "{indent}return 0;")?;
            }
            Some(pb::target::Kind::Reject(r)) => {
                self.emit_reject(w, indent, &r.reason)?;
            }
            None => bail!("empty target"),
        }
        Ok(())
    }

    fn emit_state_body(&self, w: &mut String, s: &pb::State) -> Result<()> {
        for ex in &s.extracts {
            let ht = self
                .parser
                .header_types
                .iter()
                .find(|h| h.name == ex.header_type)
                .ok_or_else(|| anyhow::anyhow!("unknown header type"))?;
            let inst = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            writeln!(w, "      out->{inst}_present = 1;")?;
            for f in &ht.fields {
                match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                    Some(pb::field_width::Width::Bits(n)) => {
                        writeln!(w, "      if (off + {n} > bit_len) {{")?;
                        self.emit_reject(w, "        ", "out of bounds")?;
                        writeln!(w, "      }}")?;
                        writeln!(
                            w,
                            "      out->{inst}.{} = ({})pk_read_bits(buf, off, {n});",
                            f.name,
                            uint_type(*n)
                        )?;
                        writeln!(w, "      off += {n};")?;
                    }
                    Some(pb::field_width::Width::ByteLen(expr)) => {
                        writeln!(w, "      {{")?;
                        writeln!(w, "        uint64_t vlen = {};", expr_c(expr)?)?;
                        // Division form: immune to u64 overflow on
                        // wrapped lengths; off <= bit_len holds here.
                        writeln!(w, "        if (vlen > (bit_len - off) / 8) {{")?;
                        self.emit_reject(w, "          ", "out of bounds")?;
                        writeln!(w, "        }}")?;
                        writeln!(w, "        out->{inst}.{}_bit_off = off;", f.name)?;
                        writeln!(w, "        out->{inst}.{}_bit_len = vlen * 8;", f.name)?;
                        writeln!(w, "        off += vlen * 8;")?;
                        writeln!(w, "      }}")?;
                    }
                    None => bail!("field `{}` has no width", f.name),
                }
            }
        }
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            None => bail!("state `{}` has no transition", s.name),
            Some(pb::transition::Kind::Direct(t)) => self.emit_target(w, "      ", t)?,
            Some(pb::transition::Kind::Select(sel)) => {
                let keys: Vec<String> = sel.keys.iter().map(expr_c).collect::<Result<_>>()?;
                for (ki, k) in keys.iter().enumerate() {
                    writeln!(w, "      uint64_t key{ki} = {k};")?;
                }
                for (i, arm) in sel.arms.iter().enumerate() {
                    let cond: Vec<String> = arm
                        .entries
                        .iter()
                        .enumerate()
                        .map(|(ki, e)| entry_c(e, &format!("key{ki}")))
                        .collect();
                    let kw = if i == 0 { "if" } else { "} else if" };
                    writeln!(w, "      {kw} ({}) {{", cond.join(" && "))?;
                    self.emit_target(
                        w,
                        "        ",
                        arm.next
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("arm without target"))?,
                    )?;
                }
                if sel.arms.is_empty() {
                    match sel.default_target.as_ref() {
                        Some(t) => self.emit_target(w, "      ", t)?,
                        None => self.emit_reject(w, "      ", "no matching select arm")?,
                    }
                } else {
                    writeln!(w, "      }} else {{")?;
                    match sel.default_target.as_ref() {
                        Some(t) => self.emit_target(w, "        ", t)?,
                        None => self.emit_reject(w, "        ", "no matching select arm")?,
                    }
                    writeln!(w, "      }}")?;
                }
            }
        }
        Ok(())
    }

    fn source(&self) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        writeln!(
            w,
            "/* Generated by pakeles from `{}`. Do not edit:",
            self.parser.name
        )?;
        writeln!(w, " * regenerate with `pakeles gen c`. */")?;
        writeln!(w, "#include \"parser.h\"")?;
        writeln!(w)?;
        w.push_str(&self.core("static")?);
        writeln!(w)?;
        writeln!(
            w,
            "int {p}_parse(const uint8_t *buf, uint64_t bit_len, {p}_result_t *out) {{"
        )?;
        writeln!(w, "  {p}_result_t zero = {{0}};")?;
        writeln!(w, "  *out = zero;")?;
        writeln!(w, "  return {p}_parse_core(buf, bit_len, out);")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        writeln!(w, "const char *{p}_reason_str(uint16_t reason) {{")?;
        writeln!(w, "  switch (reason) {{")?;
        for (reason, code) in &self.reasons {
            writeln!(w, "  case {code}: return \"{reason}\";")?;
        }
        writeln!(w, "  default: return \"\";")?;
        writeln!(w, "  }}")?;
        writeln!(w, "}}")?;
        Ok(w)
    }
}

pub fn generate_c(ir: &pb::Ir) -> Result<CArtifacts> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let emit = Emit::new(parser);
    Ok(CArtifacts {
        header: emit.header()?,
        source: emit.source()?,
    })
}

/// stdin/stdout conformance harness: one vector per line in, one
/// result line out. Test infrastructure, not a shipped artifact.
pub fn generate_c_harness(ir: &pb::Ir) -> Result<String> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let emit = Emit::new(parser);
    let p = &emit.prefix;
    let mut w = String::new();
    writeln!(
        w,
        "/* Generated conformance harness for `{}`. */",
        parser.name
    )?;
    writeln!(w, "#include \"parser.h\"")?;
    writeln!(w, "#include <stdio.h>")?;
    writeln!(w, "#include <string.h>")?;
    writeln!(w)?;
    writeln!(w, "static int hexval(int c) {{")?;
    writeln!(w, "  if (c >= '0' && c <= '9') return c - '0';")?;
    writeln!(w, "  if (c >= 'a' && c <= 'f') return c - 'a' + 10;")?;
    writeln!(w, "  return -1;")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(w, "int main(void) {{")?;
    writeln!(w, "  static char line[300000];")?;
    writeln!(w, "  static uint8_t buf[150000];")?;
    writeln!(w, "  while (fgets(line, sizeof line, stdin)) {{")?;
    writeln!(w, "    unsigned long long bit_len = 0;")?;
    writeln!(w, "    char hex[280000];")?;
    writeln!(w, "    hex[0] = 0;")?;
    writeln!(
        w,
        "    if (sscanf(line, \"%llu %279999s\", &bit_len, hex) < 1) continue;"
    )?;
    writeln!(w, "    size_t nb = strlen(hex) / 2;")?;
    writeln!(w, "    if (hex[0] == '-') nb = 0;")?;
    writeln!(w, "    for (size_t i = 0; i < nb; i++)")?;
    writeln!(
        w,
        "      buf[i] = (uint8_t)((hexval(hex[2 * i]) << 4) | hexval(hex[2 * i + 1]));"
    )?;
    writeln!(w, "    {p}_result_t r;")?;
    writeln!(w, "    {p}_parse(buf, bit_len, &r);")?;
    writeln!(
        w,
        "    printf(\"%s|%s|%llu\", r.outcome == 0 ? \"accept\" : \"reject\", {p}_reason_str(r.reason), (unsigned long long)r.consumed_bits);"
    )?;
    for (inst, ht_name) in instances(parser) {
        let ht = parser
            .header_types
            .iter()
            .find(|h| h.name == ht_name)
            .unwrap();
        writeln!(w, "    if (r.{inst}_present) {{")?;
        for f in &ht.fields {
            match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                Some(pb::field_width::Width::Bits(_)) => {
                    writeln!(
                        w,
                        "      printf(\"|{inst}.{}=%llu\", (unsigned long long)r.{inst}.{});",
                        f.name, f.name
                    )?;
                }
                Some(pb::field_width::Width::ByteLen(_)) => {
                    writeln!(w, "      printf(\"|{inst}.{}=\");", f.name)?;
                    writeln!(
                        w,
                        "      for (uint64_t i = 0; i < r.{inst}.{}_bit_len / 8; i++)",
                        f.name
                    )?;
                    writeln!(
                        w,
                        "        printf(\"%02x\", buf[r.{inst}.{}_bit_off / 8 + i]);",
                        f.name
                    )?;
                }
                None => {}
            }
        }
        writeln!(w, "    }}")?;
    }
    writeln!(w, "    printf(\"\\n\");")?;
    writeln!(w, "    fflush(stdout);")?;
    writeln!(w, "  }}")?;
    writeln!(w, "  return 0;")?;
    writeln!(w, "}}")?;
    Ok(w)
}

/// Self-contained eBPF C: same core, no libc, packed-verdict entry.
/// Harness convention: mem = 8-byte LE bit_len, then packet bytes.
pub fn generate_ebpf(ir: &pb::Ir) -> Result<String> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let emit = Emit::new(parser);
    let p = &emit.prefix;
    let mut w = String::new();
    writeln!(
        w,
        "/* Generated by pakeles from `{}` (eBPF variant). Do not edit:",
        parser.name
    )?;
    writeln!(w, " * regenerate with `pakeles gen ebpf`.")?;
    writeln!(w, " * Compile: clang -O2 -target bpf -c this_file.c")?;
    writeln!(
        w,
        " * Entry contract (rbpf raw VM): r1 = mem = 8-byte LE bit_len ++ packet;"
    )?;
    writeln!(
        w,
        " * the length prefix is the harness framing (rbpf passes no length)."
    )?;
    writeln!(
        w,
        " * Returns outcome(8b) << 56 | reason(8b) << 48 | consumed_bits(48b)."
    )?;
    writeln!(
        w,
        " * Note: the result struct lives on the (512-byte) BPF stack;"
    )?;
    writeln!(w, " * large parsers will need a redesign. */")?;
    writeln!(w)?;
    writeln!(w, "/* Freestanding: no libc for the bpf target. */")?;
    writeln!(w, "typedef __UINT8_TYPE__ uint8_t;")?;
    writeln!(w, "typedef __UINT16_TYPE__ uint16_t;")?;
    writeln!(w, "typedef __UINT32_TYPE__ uint32_t;")?;
    writeln!(w, "typedef __UINT64_TYPE__ uint64_t;")?;
    writeln!(w)?;
    w.push_str(&emit.structs()?);
    writeln!(w)?;
    writeln!(w, "typedef enum {{")?;
    writeln!(w, "  PK_R_NONE = 0,")?;
    for (reason, code) in &emit.reasons {
        writeln!(w, "  {} = {code},", reason_ident(reason))?;
    }
    writeln!(w, "}} {p}_reason_t;")?;
    writeln!(w)?;
    w.push_str(&emit.core("static __attribute__((always_inline))")?);
    writeln!(w)?;
    // rbpf's raw VM passes only the memory pointer (r1); the 8-byte
    // length prefix is the harness's framing, trusted by contract.
    writeln!(w, "uint64_t pk_entry(void *mem) {{")?;
    writeln!(w, "  const uint8_t *m = (const uint8_t *)mem;")?;
    writeln!(w, "  uint64_t bit_len = 0;")?;
    writeln!(w, "  uint32_t i;")?;
    writeln!(
        w,
        "  for (i = 0; i < 8; i++) bit_len |= (uint64_t)m[i] << (8 * i);"
    )?;
    writeln!(w, "  {p}_result_t out = {{0}};")?;
    writeln!(w, "  {p}_parse_core(m + 8, bit_len, &out);")?;
    writeln!(
        w,
        "  return ((uint64_t)out.outcome << 56) | ((uint64_t)out.reason << 48) | (out.consumed_bits & 0xFFFFFFFFFFFFULL);"
    )?;
    writeln!(w, "}}")?;
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::examples::eth_ipv4_tcp;

    fn cc_compiles(files: &[(&str, &str)], cmd: &[&str]) -> std::process::Output {
        let dir = std::env::temp_dir().join(format!("pakeles_c_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
        std::process::Command::new(cmd[0])
            .args(&cmd[1..])
            .current_dir(&dir)
            .output()
            .unwrap()
    }

    /// Full-suite conformance: the compiled C parser must agree with
    /// the reference interpreter on all 164 vectors — including the
    /// bit-granular truncations pcap could not carry to the Lua
    /// backend — on outcome, reason, consumed bits, and every field.
    #[test]
    fn c_backend_conformance_full_suite() {
        use std::io::Write as _;
        if std::process::Command::new("cc")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: cc not available");
            return;
        }
        let ir = eth_ipv4_tcp();
        let arts = generate_c(&ir).unwrap();
        let harness = generate_c_harness(&ir).unwrap();
        let dir = std::env::temp_dir().join(format!("pakeles_cconf_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("parser.h"), &arts.header).unwrap();
        std::fs::write(dir.join("parser.c"), &arts.source).unwrap();
        std::fs::write(dir.join("main.c"), &harness).unwrap();
        let cc = std::process::Command::new("cc")
            .args([
                "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2", "parser.c", "main.c", "-o",
                "harness",
            ])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            cc.status.success(),
            "cc: {}",
            String::from_utf8_lossy(&cc.stderr)
        );

        let suite = crate::testvec::suite_from_json(
            &std::fs::read_to_string("examples/eth_ipv4_tcp/vectors/vectors.json").unwrap(),
        )
        .unwrap();
        let mut input = String::new();
        let mut bits_list = Vec::new();
        for v in &suite.vectors {
            let (bits, _) = crate::testvec::Bits::from_pb(v.packet.as_ref().unwrap());
            let hex = if bits.bytes.is_empty() {
                "-".to_string()
            } else {
                crate::testvec::hex_encode(&bits.bytes)
            };
            input.push_str(&format!("{} {hex}\n", bits.bit_len));
            bits_list.push(bits);
        }
        let mut child = std::process::Command::new(dir.join("harness"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let lines: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
        assert_eq!(lines.len(), suite.vectors.len());

        let mut mismatches = Vec::new();
        for ((line, vector), bits) in lines.iter().zip(&suite.vectors).zip(&bits_list) {
            let reference = crate::interp::run_bits(&ir, bits).unwrap();
            let mut parts = line.split('|');
            let outcome = parts.next().unwrap_or("");
            let reason = parts.next().unwrap_or("");
            let consumed: u64 = parts.next().unwrap_or("0").parse().unwrap_or(u64::MAX);
            let c_fields: std::collections::HashMap<&str, &str> =
                parts.filter_map(|p| p.split_once('=')).collect();

            match &reference.outcome {
                crate::interp::Outcome::Accept => {
                    if outcome != "accept" {
                        mismatches.push(format!("{}: outcome {outcome} want accept", vector.id));
                    }
                }
                crate::interp::Outcome::Reject { reason: want } => {
                    if outcome != "reject" || reason != want {
                        mismatches.push(format!(
                            "{}: outcome/reason {outcome}/{reason} want reject/{want}",
                            vector.id
                        ));
                    }
                }
            }
            if consumed != reference.consumed_bits as u64 {
                mismatches.push(format!(
                    "{}: consumed {consumed} want {}",
                    vector.id, reference.consumed_bits
                ));
            }
            for h in &reference.headers {
                for f in &h.fields {
                    let key = format!("{}.{}", h.instance, f.name);
                    let got = c_fields.get(key.as_str()).copied();
                    let want = match &f.value {
                        crate::interp::FieldValue::Uint(u) => u.to_string(),
                        crate::interp::FieldValue::Bytes(b) => crate::testvec::hex_encode(b),
                    };
                    // The C parser records a var field's offsets only
                    // after the bounds check passes, so a field the
                    // interpreter carries as its *failure point* is
                    // simply absent — that asymmetry is fine; every
                    // *successfully extracted* field must match.
                    if let Some(got) = got {
                        if got != want {
                            mismatches.push(format!("{}: {key}={got} want {want}", vector.id));
                        }
                    } else if !matches!(&f.value, crate::interp::FieldValue::Bytes(b) if b.is_empty())
                    {
                        mismatches.push(format!("{}: {key} missing (want {want})", vector.id));
                    }
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    /// eBPF conformance: compile with clang -target bpf, extract
    /// .text, execute under the rbpf userspace VM per vector, compare
    /// the packed verdict (outcome | reason | consumed) against the
    /// reference interpreter for all 164 vectors.
    #[test]
    fn ebpf_backend_conformance_full_suite() {
        for tool in ["clang", "llvm-objcopy"] {
            if std::process::Command::new(tool)
                .arg("--version")
                .output()
                .is_err()
            {
                eprintln!("skipping: {tool} not available");
                return;
            }
        }
        let ir = eth_ipv4_tcp();
        let ebpf = generate_ebpf(&ir).unwrap();
        let dir = std::env::temp_dir().join(format!("pakeles_ebpf_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ebpf.c"), &ebpf).unwrap();
        let cc = std::process::Command::new("clang")
            .args([
                "-O2", "-target", "bpf", "-Werror", "-c", "ebpf.c", "-o", "ebpf.o",
            ])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            cc.status.success(),
            "clang: {}",
            String::from_utf8_lossy(&cc.stderr)
        );
        let oc = std::process::Command::new("llvm-objcopy")
            .args(["-O", "binary", "--only-section=.text", "ebpf.o", "ebpf.bin"])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            oc.status.success(),
            "objcopy: {}",
            String::from_utf8_lossy(&oc.stderr)
        );
        let prog = std::fs::read(dir.join("ebpf.bin")).unwrap();
        assert!(!prog.is_empty());

        let suite = crate::testvec::suite_from_json(
            &std::fs::read_to_string("examples/eth_ipv4_tcp/vectors/vectors.json").unwrap(),
        )
        .unwrap();
        let reasons = reason_table(ir.parser.as_ref().unwrap());
        let vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
        let mut mismatches = Vec::new();
        for v in &suite.vectors {
            let (bits, _) = crate::testvec::Bits::from_pb(v.packet.as_ref().unwrap());
            let reference = crate::interp::run_bits(&ir, &bits).unwrap();
            let mut mem = (bits.bit_len as u64).to_le_bytes().to_vec();
            mem.extend_from_slice(&bits.bytes);
            let verdict = vm.execute_program(&mut mem).unwrap();
            let outcome = (verdict >> 56) as u8;
            let reason_code = ((verdict >> 48) & 0xFF) as u32;
            let consumed = verdict & 0xFFFF_FFFF_FFFF;
            let reason_str = reasons
                .iter()
                .find(|(_, c)| *c == reason_code)
                .map(|(r, _)| r.as_str())
                .unwrap_or("");
            match &reference.outcome {
                crate::interp::Outcome::Accept if outcome == 0 => {}
                crate::interp::Outcome::Reject { reason }
                    if outcome == 1 && reason == reason_str => {}
                other => mismatches.push(format!(
                    "{}: verdict outcome={outcome} reason={reason_str:?}, interp {other:?}",
                    v.id
                )),
            }
            if consumed != reference.consumed_bits as u64 {
                mismatches.push(format!(
                    "{}: consumed {consumed} want {}",
                    v.id, reference.consumed_bits
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    #[test]
    fn committed_c_artifacts_current() {
        let arts = generate_c(&eth_ipv4_tcp()).unwrap();
        let ebpf = generate_ebpf(&eth_ipv4_tcp()).unwrap();
        for (path, fresh) in [
            ("examples/eth_ipv4_tcp/gen/parser.h", &arts.header),
            ("examples/eth_ipv4_tcp/gen/parser.c", &arts.source),
            ("examples/eth_ipv4_tcp/gen/ebpf.c", &ebpf),
        ] {
            let committed = std::fs::read_to_string(path).unwrap();
            assert_eq!(
                *fresh, committed,
                "examples/ drifted; regenerate: ./dev.sh cargo run --bin gen_examples"
            );
        }
    }

    #[test]
    fn generated_c_compiles_with_werror() {
        if std::process::Command::new("cc")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: cc not available");
            return;
        }
        let arts = generate_c(&eth_ipv4_tcp()).unwrap();
        let harness = generate_c_harness(&eth_ipv4_tcp()).unwrap();
        let out = cc_compiles(
            &[
                ("parser.h", &arts.header),
                ("parser.c", &arts.source),
                ("main.c", &harness),
            ],
            &[
                "cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2", "parser.c", "main.c", "-o",
                "harness",
            ],
        );
        assert!(
            out.status.success(),
            "cc failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
