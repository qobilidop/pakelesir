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
    about = "PakelesIR wire-format parser toolchain"
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
enum Oracle {
    /// Compare annotated numeric fields against `tshark -T json`.
    Tshark {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        ir: Option<PathBuf>,
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
    serde_json::json!({ "packet": idx, "outcome": outcome, "headers": headers })
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
        Command::Testgen { ir, out } => {
            let suite = crate::symex::testgen::generate(&load_ir(&ir)?)?;
            let json = crate::testvec::suite_to_json(&suite)?;
            if out.as_os_str() == "-" {
                println!("{json}");
            } else {
                std::fs::write(&out, json)?;
                eprintln!("wrote {} vectors to {}", suite.vectors.len(), out.display());
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
    fn exported_ir_loads_back() {
        let path = std::env::temp_dir().join("pakeles_export.json");
        let code = main_with(&["pakeles", "export-ir", "--out", path.to_str().unwrap()]).unwrap();
        assert_eq!(code, 0);
        let ir = crate::ir::from_json(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(ir, crate::examples::eth_ipv4_tcp());
    }
}
