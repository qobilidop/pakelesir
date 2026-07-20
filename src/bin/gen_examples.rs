//! Regenerates the examples/ gallery: every artifact one description
//! yields, committed for browsing and equality-guarded by tests.

use std::path::Path;

fn main() -> anyhow::Result<()> {
    // Role-organized gallery: top level = input + normative IR + README;
    // gen/ = everything compiled from the IR; conformance/ = the suite.
    let dir = Path::new("examples/eth_ipvx_l4");
    let gen = dir.join("gen");
    let conformance = dir.join("conformance");
    std::fs::create_dir_all(&gen)?;
    std::fs::create_dir_all(&conformance)?;
    // The eDSL is authoritative; phase 1 (scripts/gen-examples.sh) has
    // already written the canonical ir.json. Read it, don't rebuild it.
    let ir = pakeles::ir::from_json(&std::fs::read_to_string(
        dir.join("eth_ipvx_l4.ir.json"),
    )?)?;
    // The Python eDSL authoring source (the gallery's *input* twin):
    // canonical copy lives in the py package; mirrored here for browsing.
    std::fs::copy(
        "py/src/pakeles/examples/eth_ipvx_l4.py",
        dir.join("eth_ipvx_l4.py"),
    )?;

    std::fs::write(
        gen.join("dissector.lua"),
        pakeles::codegen::lua::generate_lua(&ir)?,
    )?;
    std::fs::write(gen.join("doc.md"), pakeles::docgen::generate_markdown(&ir)?)?;
    std::fs::write(gen.join("graph.dot"), pakeles::viz::to_dot(&ir))?;

    let c = pakeles::codegen::c::generate_c(&ir)?;
    std::fs::write(gen.join("parser.h"), c.header)?;
    std::fs::write(gen.join("parser.c"), c.source)?;
    std::fs::write(
        gen.join("parser.bpf.c"),
        pakeles::codegen::c::generate_bpf(&ir)?,
    )?;
    std::fs::write(
        gen.join("parser.p4"),
        pakeles::codegen::p4::generate_p4(&ir)?,
    )?;

    let suite = pakeles::symex::testgen::generate(&ir)?;
    std::fs::write(
        conformance.join("vectors.json"),
        pakeles::testvec::suite_to_json(&suite)?,
    )?;
    let (packets, _) = pakeles::testvec::suite_to_packets(&suite);
    pakeles::pcapio::write_pcap(&conformance.join("vectors.pcap"), &packets)?;

    // Best-effort SVG render (needs graphviz; fine to skip elsewhere).
    let dot = std::process::Command::new("dot")
        .arg("-Tsvg")
        .arg("-o")
        .arg(gen.join("graph.svg"))
        .arg(gen.join("graph.dot"))
        .status();
    match dot {
        Ok(s) if s.success() => {}
        _ => eprintln!("note: graph.svg not rendered (graphviz unavailable)"),
    }

    println!("examples/eth_ipvx_l4 regenerated");
    Ok(())
}
