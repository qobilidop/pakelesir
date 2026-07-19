//! The `pakeles` CLI: thin dispatch onto library functions.

use crate::interp::{FieldValue, Outcome};
use crate::ir::pb;
use anyhow::{Context, Result};
use clap::{Parser as ClapParser, Subcommand};
use std::path::PathBuf;

#[derive(ClapParser)]
#[command(
    name = "pakeles",
    version,
    about = "Pakeles wire-format parser toolchain"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse every packet in a pcap; one JSON line per packet.
    Run {
        #[arg(long)]
        pcap: PathBuf,
        /// IR file (protojson). Defaults to the built-in example.
        #[arg(long)]
        ir: Option<PathBuf>,
    },
    /// Emit the parse graph as Graphviz dot.
    Viz {
        #[arg(long)]
        ir: Option<PathBuf>,
    },
    /// Diff our parse against a reference oracle; exit 1 on mismatch.
    Diff {
        /// Which oracle to diff against (more arrive with later slices).
        #[command(subcommand)]
        oracle: Oracle,
    },
    /// Generate the path-complete conformance test-vector suite.
    #[cfg(feature = "symex")]
    Testgen {
        #[arg(long)]
        ir: Option<PathBuf>,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
        /// Also export the byte-aligned vectors as a pcap.
        #[arg(long)]
        pcap_out: Option<PathBuf>,
    },
    /// Report unreachable states and unsatisfiable select arms.
    #[cfg(feature = "symex")]
    Lint {
        #[arg(long)]
        ir: Option<PathBuf>,
    },
    /// Report which parse paths a pcap corpus exercises.
    #[cfg(feature = "symex")]
    Cov {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        ir: Option<PathBuf>,
    },
    /// Generate markdown documentation from the IR + annotations.
    Doc {
        #[arg(long)]
        ir: Option<PathBuf>,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// Generate a backend artifact from the IR.
    Gen {
        #[command(subcommand)]
        target: GenTarget,
    },
    /// Canonicalize an IR file: parse + re-emit in the canonical form
    /// (what this CLI itself writes). Other authoring surfaces (the
    /// Python eDSL) pipe through this before equality comparisons.
    FmtIr {
        /// IR file (protojson) to canonicalize.
        #[arg(long)]
        ir: PathBuf,
        /// Output path; `-` for stdout. Defaults to stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// Write the built-in example IR (the file other tools consume).
    ExportIr {
        /// Output path; `-` for stdout (JSON only).
        #[arg(long, default_value = "-")]
        out: PathBuf,
        #[arg(long)]
        binary: bool,
    },
}

#[derive(Subcommand)]
enum GenTarget {
    /// Wireshark Lua dissector (direct translation, Lua 5.2).
    Lua {
        #[arg(long)]
        ir: Option<PathBuf>,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// Portable C99 parser (<name>.h + <name>.c).
    C {
        #[arg(long)]
        ir: Option<PathBuf>,
        /// Directory to write parser.h and parser.c into.
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
    },
    /// Self-contained eBPF C variant.
    Ebpf {
        #[arg(long)]
        ir: Option<PathBuf>,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// P4-16 program for the v1model architecture (BMv2-runnable).
    P4 {
        #[arg(long)]
        ir: Option<PathBuf>,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum Oracle {
    /// Compare annotated numeric fields against `tshark -T json`.
    Tshark {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        ir: Option<PathBuf>,
    },
    /// Verdict-compare the byte-aligned vectors against BMv2 simple_switch.
    Bmv2 {
        #[arg(long)]
        ir: Option<PathBuf>,
        /// Vector suite (testvec JSON). Defaults to the gallery suite.
        #[arg(long, default_value = "examples/eth_ipv4_tcp/vectors/vectors.json")]
        vectors: PathBuf,
    },
}

fn load_ir(path: &Option<PathBuf>) -> Result<pb::Ir> {
    match path {
        None => Ok(crate::examples::eth_ipv4_tcp()),
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading IR from {}", p.display()))?;
            let ir = crate::ir::from_json(&text)?;
            crate::ir::validate::validate(&ir)
                .map_err(|e| anyhow::anyhow!("invalid IR:\n  {}", e.join("\n  ")))?;
            Ok(ir)
        }
    }
}

fn result_json(idx: usize, res: &crate::interp::ParseResult) -> serde_json::Value {
    let headers: Vec<serde_json::Value> = res
        .headers
        .iter()
        .map(|h| {
            let fields: serde_json::Map<String, serde_json::Value> = h
                .fields
                .iter()
                .map(|f| {
                    let v = match &f.value {
                        FieldValue::Uint(u) => serde_json::json!(u),
                        FieldValue::Bytes(b) => serde_json::json!(b
                            .iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<String>()),
                    };
                    (f.name.clone(), v)
                })
                .collect();
            serde_json::json!({ "instance": h.instance, "fields": fields })
        })
        .collect();
    let outcome = match &res.outcome {
        Outcome::Accept => serde_json::json!("accept"),
        Outcome::Reject { reason } => serde_json::json!({ "reject": reason }),
    };
    let error = res.error.as_ref().map(|e| {
        serde_json::json!({
            "state": e.state,
            "instance": e.instance,
            "field": e.field,
            "bit_offset": e.bit_offset,
            "reason": e.reason,
            "severity": match e.severity {
                crate::interp::Severity::Error => "error",
                crate::interp::Severity::Info => "info",
            },
        })
    });
    serde_json::json!({
        "packet": idx,
        "outcome": outcome,
        "headers": headers,
        "error": error,
        "payload_bit_off": res.consumed_bits,
    })
}

/// Entry point returning a process exit code (testable without a process).
pub fn main_with(args: &[&str]) -> Result<i32> {
    let cli = Cli::try_parse_from(args)?;
    match cli.command {
        Command::Run { pcap, ir } => {
            let ir = load_ir(&ir)?;
            for (idx, packet) in crate::pcapio::read_packets(&pcap)?.iter().enumerate() {
                let res = crate::interp::run(&ir, packet)?;
                println!("{}", result_json(idx, &res));
            }
            Ok(0)
        }
        Command::Viz { ir } => {
            print!("{}", crate::viz::to_dot(&load_ir(&ir)?));
            Ok(0)
        }
        Command::Diff {
            oracle: Oracle::Bmv2 { ir, vectors },
        } => {
            let ir = load_ir(&ir)?;
            let suite = crate::testvec::suite_from_json(&std::fs::read_to_string(&vectors)?)?;
            let report = crate::oracle::bmv2::diff_suite(&ir, &suite)?;
            println!(
                "{} vectors compared ({} bit-granular skipped), {} mismatches",
                report.compared,
                report.skipped_bit_granular,
                report.mismatches.len()
            );
            for m in &report.mismatches {
                println!("  {m}");
            }
            Ok(if report.mismatches.is_empty() { 0 } else { 1 })
        }
        Command::Diff {
            oracle: Oracle::Tshark { pcap, ir },
        } => {
            let report = crate::oracle::diff_pcap(&load_ir(&ir)?, &pcap)?;
            println!(
                "{} packets, {} fields compared, {} mismatches",
                report.packets,
                report.compared,
                report.mismatches.len()
            );
            for m in &report.mismatches {
                println!(
                    "  packet {} {}: ours={:#x} tshark={} ({:?})",
                    m.packet, m.tshark_key, m.ours, m.raw, m.theirs
                );
            }
            Ok(if report.mismatches.is_empty() { 0 } else { 1 })
        }
        #[cfg(feature = "symex")]
        Command::Lint { ir } => {
            let findings = crate::symex::lint::lint(&load_ir(&ir)?)?;
            for f in &findings {
                println!("{}: {}", f.location, f.message);
            }
            if findings.is_empty() {
                println!("clean");
            }
            Ok(if findings.is_empty() { 0 } else { 1 })
        }
        #[cfg(feature = "symex")]
        Command::Cov { pcap, ir } => {
            let cov = crate::symex::cov::coverage(&load_ir(&ir)?, &pcap)?;
            println!(
                "{} packets exercised {}/{} paths",
                cov.packets,
                cov.hits.len(),
                cov.total
            );
            for (id, n) in &cov.hits {
                println!("  {n:>6}  {id}");
            }
            println!("{} paths unexercised", cov.unexercised.len());
            Ok(0)
        }
        #[cfg(feature = "symex")]
        Command::Testgen { ir, out, pcap_out } => {
            let suite = crate::symex::testgen::generate(&load_ir(&ir)?)?;
            let json = crate::testvec::suite_to_json(&suite)?;
            if out.as_os_str() == "-" {
                println!("{json}");
            } else {
                std::fs::write(&out, json)?;
                eprintln!("wrote {} vectors to {}", suite.vectors.len(), out.display());
            }
            if let Some(pcap) = pcap_out {
                let (packets, indices) = crate::testvec::suite_to_packets(&suite);
                crate::pcapio::write_pcap(&pcap, &packets)?;
                eprintln!(
                    "wrote {} byte-aligned vectors to {} ({} bit-granular vectors skipped)",
                    packets.len(),
                    pcap.display(),
                    suite.vectors.len() - indices.len()
                );
            }
            Ok(0)
        }
        Command::Doc { ir, out } => {
            let md = crate::docgen::generate_markdown(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{md}");
            } else {
                std::fs::write(&out, md)?;
            }
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::Lua { ir, out },
        } => {
            let lua = crate::codegen::lua::generate_lua(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{lua}");
            } else {
                std::fs::write(&out, lua)?;
            }
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::C { ir, out_dir },
        } => {
            let arts = crate::codegen::c::generate_c(&load_ir(&ir)?)?;
            std::fs::create_dir_all(&out_dir)?;
            std::fs::write(out_dir.join("parser.h"), arts.header)?;
            std::fs::write(out_dir.join("parser.c"), arts.source)?;
            eprintln!("wrote parser.h + parser.c to {}", out_dir.display());
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::Ebpf { ir, out },
        } => {
            let c = crate::codegen::c::generate_ebpf(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{c}");
            } else {
                std::fs::write(&out, c)?;
            }
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::P4 { ir, out },
        } => {
            let p4 = crate::codegen::p4::generate_p4(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{p4}");
            } else {
                std::fs::write(&out, p4)?;
            }
            Ok(0)
        }
        Command::FmtIr { ir, out } => {
            let text = std::fs::read_to_string(&ir)
                .with_context(|| format!("reading IR from {}", ir.display()))?;
            let canonical = crate::ir::to_json(&crate::ir::from_json(&text)?)?;
            if out.as_os_str() == "-" {
                println!("{canonical}");
            } else {
                std::fs::write(&out, canonical)?;
            }
            Ok(0)
        }
        Command::ExportIr { out, binary } => {
            let ir = crate::examples::eth_ipv4_tcp();
            if out.as_os_str() == "-" {
                print!("{}", crate::ir::to_json(&ir)?);
            } else if binary {
                std::fs::write(&out, crate::ir::to_bytes(&ir))?;
            } else {
                std::fs::write(&out, crate::ir::to_json(&ir)?)?;
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::main_with;

    #[test]
    fn run_on_fixture_ok() {
        let code = main_with(&["pakeles", "run", "--pcap", "testdata/basic.pcap"]).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn diff_tshark_on_fixture_green() {
        if std::process::Command::new("tshark")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: tshark not available");
            return;
        }
        let code =
            main_with(&["pakeles", "diff", "tshark", "--pcap", "testdata/basic.pcap"]).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn viz_ok() {
        assert_eq!(main_with(&["pakeles", "viz"]).unwrap(), 0);
    }

    #[test]
    fn fmt_ir_canonicalizes_mangled_json() {
        let ir = crate::examples::eth_ipv4_tcp();
        let canonical = crate::ir::to_json(&ir).unwrap();
        // Same document, hostile formatting: compact everything.
        let mangled =
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&canonical).unwrap())
                .unwrap();
        let dir = std::env::temp_dir().join("pakeles_fmt_ir");
        std::fs::create_dir_all(&dir).unwrap();
        let inp = dir.join("mangled.json");
        let outp = dir.join("out.json");
        std::fs::write(&inp, mangled).unwrap();
        let code = main_with(&[
            "pakeles",
            "fmt-ir",
            "--ir",
            inp.to_str().unwrap(),
            "--out",
            outp.to_str().unwrap(),
        ])
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(std::fs::read_to_string(&outp).unwrap(), canonical);
    }

    #[test]
    fn exported_ir_loads_back() {
        let path = std::env::temp_dir().join("pakeles_export.json");
        let code = main_with(&["pakeles", "export-ir", "--out", path.to_str().unwrap()]).unwrap();
        assert_eq!(code, 0);
        let ir = crate::ir::from_json(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(ir, crate::examples::eth_ipv4_tcp());
    }
}
