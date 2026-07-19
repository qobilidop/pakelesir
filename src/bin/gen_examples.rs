//! Regenerates the examples/ gallery: every artifact one description
//! yields, committed for browsing and equality-guarded by tests.

use std::path::Path;

fn main() -> anyhow::Result<()> {
    // Role-organized gallery: top level = input + normative IR + README;
    // gen/ = everything compiled from the IR; vectors/ = the suite.
    let dir = Path::new("examples/eth_ipv4_tcp");
    let gen = dir.join("gen");
    let vectors = dir.join("vectors");
    std::fs::create_dir_all(&gen)?;
    std::fs::create_dir_all(&vectors)?;
    let ir = pakeles::examples::eth_ipv4_tcp();

    std::fs::write(dir.join("ir.json"), pakeles::ir::to_json(&ir)?)?;
    // The Python eDSL authoring source (the gallery's *input* twin):
    // canonical copy lives in the py package; mirrored here for browsing.
    std::fs::copy(
        "py/src/pakeles/examples/eth_ipv4_tcp.py",
        dir.join("eth_ipv4_tcp.py"),
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
    std::fs::write(gen.join("ebpf.c"), pakeles::codegen::c::generate_ebpf(&ir)?)?;
    std::fs::write(
        gen.join("parser.p4"),
        pakeles::codegen::p4::generate_p4(&ir)?,
    )?;

    let suite = pakeles::symex::testgen::generate(&ir)?;
    std::fs::write(
        vectors.join("vectors.json"),
        pakeles::testvec::suite_to_json(&suite)?,
    )?;
    let (packets, _) = pakeles::testvec::suite_to_packets(&suite);
    pakeles::pcapio::write_pcap(&vectors.join("vectors.pcap"), &packets)?;

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

    println!("examples/eth_ipv4_tcp regenerated");
    Ok(())
}
