//! Regenerates the examples/ gallery: every artifact one description
//! yields, committed for browsing and equality-guarded by tests.

use std::path::Path;

fn main() -> anyhow::Result<()> {
    let dir = Path::new("examples/eth_ipv4_tcp");
    std::fs::create_dir_all(dir)?;
    let ir = pakeles::examples::eth_ipv4_tcp();

    std::fs::write(dir.join("ir.json"), pakeles::ir::to_json(&ir)?)?;
    std::fs::write(
        dir.join("dissector.lua"),
        pakeles::codegen::lua::generate_lua(&ir)?,
    )?;
    std::fs::write(dir.join("doc.md"), pakeles::docgen::generate_markdown(&ir)?)?;
    std::fs::write(dir.join("graph.dot"), pakeles::viz::to_dot(&ir))?;

    let suite = pakeles::symex::testgen::generate(&ir)?;
    std::fs::write(
        dir.join("vectors.json"),
        pakeles::testvec::suite_to_json(&suite)?,
    )?;
    let (packets, _) = pakeles::testvec::suite_to_packets(&suite);
    pakeles::pcapio::write_pcap(&dir.join("vectors.pcap"), &packets)?;

    // Best-effort SVG render (needs graphviz; fine to skip elsewhere).
    let dot = std::process::Command::new("dot")
        .arg("-Tsvg")
        .arg("-o")
        .arg(dir.join("graph.svg"))
        .arg(dir.join("graph.dot"))
        .status();
    match dot {
        Ok(s) if s.success() => {}
        _ => eprintln!("note: graph.svg not rendered (graphviz unavailable)"),
    }

    println!("examples/eth_ipv4_tcp regenerated");
    Ok(())
}
