//! Envelopes over MLS application messages.

use gim_common::{DeviceRef, GroupId};
use gim_proto::envelope::{self, Envelope};

use crate::{CryptoError, CryptoStore, MlsEngine, ProcessedMessage};

/// An incoming group message after decryption.
// Short-lived and moved once; boxing would only complicate matching.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptedMessage {
    Envelope {
        sender: DeviceRef,
        epoch: u64,
        envelope: Envelope,
    },
    /// A commit or proposal; already applied by [`MlsEngine::process_message`].
    Handshake(ProcessedMessage),
}

/// Encodes `envelope` and encrypts it as an MLS application message.
pub fn encrypt_envelope(
    engine: &MlsEngine,
    store: &impl CryptoStore,
    group_id: &GroupId,
    envelope: &Envelope,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = envelope::encode(envelope).map_err(CryptoError::invalid_envelope)?;
    engine.encrypt(store, group_id, &plaintext)
}

/// Processes an incoming group message and decodes application plaintext
/// as an [`Envelope`].
///
/// An application message whose plaintext is not a valid envelope returns
/// `InvalidInput`; its MLS ratchet state has already been consumed.
pub fn decrypt_to_envelope(
    engine: &MlsEngine,
    store: &impl CryptoStore,
    group_id: &GroupId,
    message: &[u8],
) -> Result<DecryptedMessage, CryptoError> {
    match engine.process_message(store, group_id, message)? {
        ProcessedMessage::Application {
            sender,
            plaintext,
            epoch,
        } => Ok(DecryptedMessage::Envelope {
            sender,
            epoch,
            envelope: envelope::decode(&plaintext).map_err(CryptoError::invalid_envelope)?,
        }),
        other => Ok(DecryptedMessage::Handshake(other)),
    }
}

impl CryptoError {
    fn invalid_envelope(err: gim_proto::ProtoError) -> Self {
        Self::invalid(format!("envelope: {err}"))
    }
}
