//! Serde helpers for standard-base64 binary fields
//! (`#[serde(with = "...")]`), and [`url_option`] for base64url ones.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{de, Deserialize, Deserializer, Serializer};

fn decode<E: de::Error>(text: &str) -> Result<Vec<u8>, E> {
    STANDARD.decode(text).map_err(E::custom)
}

/// `Vec<u8>` as one base64 string.
pub mod bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        decode(&String::deserialize(deserializer)?)
    }
}

/// `Option<Vec<u8>>` as an optional base64 string. Pair with
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`.
pub mod option {
    use super::*;

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| decode(&text))
            .transpose()
    }
}

/// `Vec<Vec<u8>>` as an array of base64 strings.
pub mod list {
    use super::*;
    use serde::ser::SerializeSeq;

    pub fn serialize<S: Serializer>(items: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(items.len()))?;
        for item in items {
            seq.serialize_element(&STANDARD.encode(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|text| decode(text))
            .collect()
    }
}

/// `Option<Vec<u8>>` as an optional base64url string without padding. Pair
/// with `#[serde(default, skip_serializing_if = "Option::is_none")]`.
pub mod url_option {
    use super::*;

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&URL_SAFE_NO_PAD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| URL_SAFE_NO_PAD.decode(text).map_err(de::Error::custom))
            .transpose()
    }
}
