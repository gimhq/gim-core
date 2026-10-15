//! Deterministic CBOR helpers shared by the signed formats.

use ciborium::Value;

use crate::{IdentityError, FORMAT_VERSION};

fn decode_error(reason: impl Into<String>) -> IdentityError {
    IdentityError::Decode(reason.into())
}

pub(crate) fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("writing CBOR to a Vec cannot fail");
    bytes
}

/// Decodes one data item and requires `bytes` to be exactly its
/// deterministic encoding (definite lengths, shortest heads, no trailing
/// bytes).
pub(crate) fn decode(bytes: &[u8]) -> Result<Value, IdentityError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|e| decode_error(e.to_string()))?;
    if encode(&value) != bytes {
        return Err(decode_error("not deterministic CBOR"));
    }
    Ok(value)
}

/// Signed form: `[tbs: bstr, sig: bstr(64)]`.
pub(crate) fn encode_signed(tbs: &[u8], sig: &[u8; 64]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Bytes(tbs.to_vec()),
        Value::Bytes(sig.to_vec()),
    ]))
}

pub(crate) fn decode_signed(bytes: &[u8]) -> Result<(Vec<u8>, [u8; 64]), IdentityError> {
    let [tbs, sig] = array(decode(bytes)?)?;
    let sig = bytes_value(sig)?
        .try_into()
        .map_err(|_| decode_error("signature is not 64 bytes"))?;
    Ok((bytes_value(tbs)?, sig))
}

/// Decodes a signed body: an array of exactly `N` items whose first item is
/// [`FORMAT_VERSION`].
pub(crate) fn decode_body<const N: usize>(tbs: &[u8]) -> Result<[Value; N], IdentityError> {
    let Value::Array(items) = decode(tbs)? else {
        return Err(decode_error("body is not an array"));
    };
    let version = uint(
        items
            .first()
            .cloned()
            .ok_or_else(|| decode_error("empty body"))?,
    )?;
    if version != FORMAT_VERSION {
        return Err(IdentityError::UnsupportedVersion(version));
    }
    array(Value::Array(items))
}

pub(crate) fn array<const N: usize>(value: Value) -> Result<[Value; N], IdentityError> {
    let Value::Array(items) = value else {
        return Err(decode_error("expected an array"));
    };
    items
        .try_into()
        .map_err(|_| decode_error(format!("expected an array of {N} items")))
}

pub(crate) fn list(value: Value) -> Result<Vec<Value>, IdentityError> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(decode_error("expected an array")),
    }
}

pub(crate) fn uint(value: Value) -> Result<u64, IdentityError> {
    match value {
        Value::Integer(int) => u64::try_from(int).map_err(|_| decode_error("expected a uint")),
        _ => Err(decode_error("expected a uint")),
    }
}

pub(crate) fn text(value: Value) -> Result<String, IdentityError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(decode_error("expected a text string")),
    }
}

pub(crate) fn bytes_value(value: Value) -> Result<Vec<u8>, IdentityError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(decode_error("expected a byte string")),
    }
}

pub(crate) fn key(value: Value) -> Result<[u8; 32], IdentityError> {
    bytes_value(value)?
        .try_into()
        .map_err(|_| decode_error("public key is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_deterministic_encodings() {
        // uint 1 with a one-byte argument.
        assert!(decode(&[0x18, 0x01]).is_err());
        // Indefinite-length array [1].
        assert!(decode(&[0x9f, 0x01, 0xff]).is_err());
        // Trailing byte.
        assert!(decode(&[0x01, 0x01]).is_err());
        assert_eq!(decode(&[0x82, 0x01, 0x40]).unwrap(), {
            Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![])])
        });
    }

    #[test]
    fn body_version_and_length() {
        let body = |items: Vec<Value>| encode(&Value::Array(items));
        let one = || Value::Integer(1.into());
        assert!(matches!(
            decode_body::<2>(&body(vec![Value::Integer(2.into()), one()])),
            Err(IdentityError::UnsupportedVersion(2))
        ));
        assert!(decode_body::<2>(&body(vec![one()])).is_err());
        assert!(decode_body::<2>(&body(vec![one(), one()])).is_ok());
    }
}
