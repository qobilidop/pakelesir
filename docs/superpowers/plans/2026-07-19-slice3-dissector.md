# PakelesIR Slice 3 ("The Dissector") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Per `../specs/2026-07-19-slice3-design.md`: diagnose-enriched interpreter results, typed Display annotations, `gen lua` (direct-translation Wireshark dissector), `testgen --pcap-out`, tshark-with-our-dissector conformance, `doc`.

**Global constraints:** as slice 2 (dev.sh gate, proto-first, loud caps, commit per green task, trailer). Generated Lua must run on Lua 5.2.

### Task 1: schema — Display + Reject.annotations (+ validation + example)
`ir.proto`: `Field` gains `Display display = 3`; new top-level `Display{string name=1; DisplayFormat format=2; repeated ValueLabel value_labels=3; string doc=4}`, `enum DisplayFormat{UNSPECIFIED/DEC/HEX/BIN/IPV4/IPV6/ETHER}`, `ValueLabel{uint64 value=1; string label=2}`; `Reject` gains `map<string,string> annotations = 15`. Builder: `disp(name, DisplayFormat) -> Display` + `.labels(&[(u64,&str)])` + `.doc(&str)` chainers; `HeaderTypeBuilder::bits_full(name, n, Option<Display>, anns)` with existing methods delegating; `reject_info(reason)` target helper (severity=info). Validation: label values fit width, no duplicate label values, severity value ∈ {error,info}. Example: full Display coverage; ethertype labels {0x0800 IPv4, 0x86DD IPv6, 0x8100 VLAN}; protocol labels {1 ICMP, 6 TCP, 17 UDP}; ipv4 src/dst IPV4 + tshark keys ip.src/ip.dst; eth dst/src ETHER + eth.dst/eth.src; both authored rejects become `reject_info`. Tests: validation rules; snapshot refresh. `buf lint` + `buf breaking` sanity.

### Task 2: interpreter diagnose enrichment
`ParseResult` gains `error: Option<ParseError{state, instance: Option<String>, field: Option<String>, bit_offset, reason, severity}>` and `consumed_bits: usize`; `Severity{Error,Info}` from Reject annotations (default Error; oob/depth/no-match Error). CLI `run` JSON gains `error`/`payload` fields. Tests: truncated packet reports instance/field/offset; UDP packet reports severity Info at consumed boundary; accept has `error: None`, consumed_bits = parse length.

### Task 3: oracle format-aware normalization
`normalize_typed(raw, DisplayFormat) -> Option<u64>`: IPV4 dotted quad → u32, ETHER colon-hex → u48, else numeric fallback. `diff_pcap` uses the field's Display format. Fixture comparisons rise 16 → 24 (four address fields × 2 accepted packets). Tests: unit normalize cases + updated integration count.

### Task 4: vectors→pcap export
`testvec::suite_to_pcap(&TestSuite) -> (Vec<Vec<u8>> packets, Vec<usize> vector_indices)` selecting byte-aligned vectors in order; CLI `testgen --pcap-out <file>` (with `--out` still writing JSON) printing exported/skipped counts. Test: fixture suite exports the byte-aligned subset, indices map back to matching ids.

### Task 5: `gen lua` — the dissector generator
`src/codegen/mod.rs` + `src/codegen/lua.rs`: `generate_lua(&pb::Ir) -> Result<String>` by direct string emission (no template dep). Structure: header comment (provenance + Lua-5.2 note); `Proto`; ProtoFields per (inst,field) with abbrev `pakeles_<parser>.<inst>.<field>`, typed ether/ipv4 where statically byte-aligned (alignment analysis: cursor mod 8 propagated across states; conflict → unknown → uint fallback), value-label tables, base from format; two ProtoExperts (error/info); per-state functions `state_<name>(buf, pinfo, tree, off, depth)`: depth guard, per-field bounds check → expert + return, extraction (locals only for IR-referenced fields), select → if/elseif chains using entry conditions (value/masked via bit arithmetic on numbers — masks via `bitfield` values and arithmetic-safe comparisons; Lua 5.2: use `bit32` only for ≤32-bit masked entries, error at generation time on >32-bit masked keys — loud cap, revisit when needed), targets → tail calls / accept (payload subtree) / reject (expert by severity; info renders payload); registration `DissectorTable.get("wtap_encap"):add(1, p)`. CLI: `gen lua [--ir] [--out]`. Tests: insta snapshot of generated Lua; generation errors on >32-bit masked select keys.

### Task 6: conformance — tshark runs our dissector
`src/codegen/luaconf.rs` (cfg(test)-adjacent helper in oracle?): write generated lua + exported pcap to temp; run `tshark -X lua_script:<file> -r <pcap> -T json`; for each exported vector, look up `pakeles_<parser>.<inst>.<field>` keys (recursive lookup reused), normalize via Display formats, compare against expected fields (all headers present in expected, including partial ones for byte-aligned truncation/reject vectors). Integration test `generated_dissector_conformance` (skip-if-no-tshark guard). Debug loop budgeted: tshark Lua errors print to stderr — surface them in the test failure.

### Task 7: `doc` generator + close-out
`src/docgen.rs`: markdown — title (parser, ir_version), per-header table (Field | Bits | Format | Name | Labels | Doc), state/transition list (reusing viz's entry formatter), payload/reject severity notes. CLI `doc [--ir] [--out]`. Snapshot test. Close-out: full gate both feature configs, README (gen lua / doc / --pcap-out in quickstart, slice-3 status), spec drift check, memory update, merge, push.
