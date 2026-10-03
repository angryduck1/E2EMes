//! Serde helpers that encode binary fields as lowercase hex strings in JSON.

use serde::{de::Error, Deserialize, Deserializer, Serializer};

pub mod bytes {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = <&str>::deserialize(d)?;
        hex::decode(text).map_err(D::Error::custom)
    }
}

pub mod key {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = <&str>::deserialize(d)?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(text, &mut out).map_err(D::Error::custom)?;
        Ok(out)
    }
}
