use std::fmt;

use serde::{Deserialize, Serialize};

use crate::GimCommonError;

/// Maximum length of any id, in bytes.
pub const MAX_ID_LEN: usize = 128;

fn validate(kind: &'static str, value: &str, slash: bool) -> Result<(), GimCommonError> {
    let reason = if value.is_empty() {
        "empty"
    } else if value.len() > MAX_ID_LEN {
        "longer than 128 bytes"
    } else if !slash && value.contains('/') {
        "contains '/'"
    } else {
        return Ok(());
    };
    Err(GimCommonError::InvalidId {
        kind,
        reason: reason.to_string(),
    })
}

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        string_id!($(#[$meta])* $name, $kind, false, "no '/'");
    };
    ($(#[$meta:meta])* $name:ident, $kind:literal, $slash:literal, $rule:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validates and wraps an id: non-empty, at most 128 bytes, ", $rule, ".")]
            pub fn new(value: impl Into<String>) -> Result<Self, GimCommonError> {
                let value = value.into();
                validate($kind, &value, $slash)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = GimCommonError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

string_id!(
    /// A gim-server user id.
    UserId,
    "user id"
);
string_id!(
    /// A gim-server device id (unique per user).
    DeviceId,
    "device id"
);
string_id!(
    /// A hub group id, `<owner hub_id>/<random>`; also the MLS GroupId (its
    /// UTF-8 bytes). Unlike the other ids it may contain '/'.
    GroupId,
    "group id",
    true,
    "'/' allowed"
);
string_id!(
    /// Client-chosen idempotency key for a posted message.
    ClientId,
    "client id"
);
string_id!(
    /// A message id.
    MessageId,
    "message id"
);

/// A device of a user; displayed as `"{user_id}/{device_id}"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceRef {
    pub user_id: UserId,
    pub device_id: DeviceId,
}

impl DeviceRef {
    pub fn new(user_id: UserId, device_id: DeviceId) -> Self {
        Self { user_id, device_id }
    }

    /// Validates both parts and builds a device reference.
    pub fn parse(user_id: &str, device_id: &str) -> Result<Self, GimCommonError> {
        Ok(Self::new(UserId::new(user_id)?, DeviceId::new(device_id)?))
    }
}

impl fmt::Display for DeviceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.user_id, self.device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ids() {
        let id = UserId::new("alice").unwrap();
        assert_eq!(id.as_str(), "alice");
        assert_eq!(id.to_string(), "alice");
        assert!(GroupId::new("x".repeat(MAX_ID_LEN)).is_ok());
        assert!(GroupId::new("hub/group").is_ok());
    }

    #[test]
    fn invalid_ids() {
        for value in [String::new(), "a/b".into(), "x".repeat(MAX_ID_LEN + 1)] {
            assert!(matches!(
                DeviceId::new(value.clone()),
                Err(GimCommonError::InvalidId {
                    kind: "device id",
                    ..
                })
            ));
            assert!(ClientId::new(value.clone()).is_err());
            assert!(MessageId::new(value).is_err());
        }
    }

    #[test]
    fn serde_validates() {
        let id: GroupId = serde_json::from_str("\"g1\"").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"g1\"");
        assert!(serde_json::from_str::<UserId>("\"a/b\"").is_err());
        assert!(serde_json::from_str::<GroupId>("\"\"").is_err());
    }
}
