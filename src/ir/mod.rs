//! The normative IR: generated protobuf types plus serialization helpers.
//! This module depends on no other module in the crate.

#[allow(clippy::all)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/pakeles.ir.v1alpha1.rs"));
    include!(concat!(env!("OUT_DIR"), "/pakeles.ir.v1alpha1.serde.rs"));
}

pub mod validate;

pub const IR_VERSION: &str = "0.1.0";

use anyhow::Result;
use prost::Message;

pub fn to_bytes(ir: &pb::Ir) -> Vec<u8> {
    ir.encode_to_vec()
}

pub fn from_bytes(b: &[u8]) -> Result<pb::Ir> {
    Ok(pb::Ir::decode(b)?)
}

pub fn to_json(ir: &pb::Ir) -> Result<String> {
    Ok(serde_json::to_string_pretty(ir)?)
}

pub fn from_json(s: &str) -> Result<pb::Ir> {
    Ok(serde_json::from_str(s)?)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::pb;

    pub fn tiny() -> pb::Ir {
        pb::Ir {
            ir_version: super::IR_VERSION.into(),
            parser: Some(pb::Parser {
                name: "tiny".into(),
                max_depth: 1,
                start_state: "s".into(),
                states: vec![pb::State {
                    name: "s".into(),
                    transition: Some(pb::Transition {
                        kind: Some(pb::transition::Kind::Direct(pb::Target {
                            kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                        })),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_binary_and_json() {
        let ir = test_support::tiny();
        assert_eq!(from_bytes(&to_bytes(&ir)).unwrap(), ir);
        assert_eq!(from_json(&to_json(&ir).unwrap()).unwrap(), ir);
    }
}
