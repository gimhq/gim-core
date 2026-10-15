//! Hub-side reading of MLS framing: the epoch of any group message, and the
//! membership changes of a handshake message sent as PublicMessage. No group
//! state is needed; credentials of added members are parsed and their chain
//! verified, but nothing is validated against a DeviceList.

use gim_common::DeviceRef;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _, VLBytes};
use openmls::prelude::{
    ContentType, GroupEpoch, GroupId as MlsGroupId, KeyPackageIn, ProposalIn, ProposalOrRefIn,
    ProtocolVersion, Sender,
};
use openmls_rust_crypto::RustCrypto;

use crate::engine::{deserialize, device_of};
use crate::CryptoError;

/// MLS protocol version 1.0.
const MLS10: u16 = 1;
/// `WireFormat` of a PublicMessage.
const PUBLIC_MESSAGE: u16 = 1;

/// Whether a handshake message is a Commit or a standalone Proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    Commit,
    Proposal,
}

/// What a hub reads from a PublicMessage handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInfo {
    /// MLS GroupId bytes.
    pub group_id: Vec<u8>,
    /// Epoch the message was sent in.
    pub epoch: u64,
    /// Leaf index of the sending member; `None` for other senders.
    pub sender_leaf: Option<u32>,
    pub kind: HandshakeKind,
    /// Devices added by inline Add proposals, in proposal order.
    pub added: Vec<DeviceRef>,
    /// Leaves removed by inline Remove proposals (and the sender's own leaf
    /// for a SelfRemove), in proposal order.
    pub removed_leaves: Vec<u32>,
    /// Proposals included by reference; their content is not visible here.
    pub referenced: usize,
}

/// The epoch in the framing of a PublicMessage or PrivateMessage.
pub fn message_epoch(message: &[u8]) -> Result<u64, CryptoError> {
    let message = deserialize(message)?
        .try_into_protocol_message()
        .map_err(|_| CryptoError::invalid("message is not a group message"))?;
    Ok(message.epoch().as_u64())
}

/// Parses an MLSMessage carrying a Commit or Proposal as PublicMessage.
pub fn inspect_handshake(message: &[u8]) -> Result<HandshakeInfo, CryptoError> {
    let malformed =
        |e: &dyn std::fmt::Display| CryptoError::invalid(format!("malformed handshake: {e}"));
    let mut bytes = message;
    let version = read_u16(&mut bytes)?;
    let wire_format = read_u16(&mut bytes)?;
    if version != MLS10 || wire_format != PUBLIC_MESSAGE {
        return Err(CryptoError::invalid(
            "message is not an MLS 1.0 PublicMessage",
        ));
    }
    let group_id = MlsGroupId::tls_deserialize(&mut bytes).map_err(|e| malformed(&e))?;
    let epoch = GroupEpoch::tls_deserialize(&mut bytes).map_err(|e| malformed(&e))?;
    let sender = Sender::tls_deserialize(&mut bytes).map_err(|e| malformed(&e))?;
    VLBytes::tls_deserialize(&mut bytes).map_err(|e| malformed(&e))?;
    let content_type = ContentType::tls_deserialize(&mut bytes).map_err(|e| malformed(&e))?;
    let sender_leaf = match sender {
        Sender::Member(leaf) => Some(leaf.u32()),
        _ => None,
    };
    let mut info = HandshakeInfo {
        group_id: group_id.as_slice().to_vec(),
        epoch: epoch.as_u64(),
        sender_leaf,
        kind: HandshakeKind::Commit,
        added: Vec::new(),
        removed_leaves: Vec::new(),
        referenced: 0,
    };
    match content_type {
        ContentType::Commit => {
            let proposals =
                Vec::<ProposalOrRefIn>::tls_deserialize(&mut bytes).map_err(|e| malformed(&e))?;
            for proposal in proposals {
                match proposal {
                    ProposalOrRefIn::Proposal(proposal) => info.record(*proposal)?,
                    ProposalOrRefIn::Reference(_) => info.referenced += 1,
                }
            }
        }
        ContentType::Proposal => {
            info.kind = HandshakeKind::Proposal;
            let proposal = ProposalIn::tls_deserialize(&mut bytes).map_err(|e| malformed(&e))?;
            info.record(proposal)?;
        }
        ContentType::Application => {
            return Err(CryptoError::invalid("message is not a handshake message"))
        }
    }
    Ok(info)
}

impl HandshakeInfo {
    fn record(&mut self, proposal: ProposalIn) -> Result<(), CryptoError> {
        match proposal {
            ProposalIn::Add(add) => {
                // An Add body is exactly a KeyPackage.
                let encoded = add.tls_serialize_detached().map_err(CryptoError::mls)?;
                let key_package = KeyPackageIn::tls_deserialize_exact(encoded)
                    .map_err(CryptoError::mls)?
                    .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
                    .map_err(|e| CryptoError::invalid(format!("invalid KeyPackage: {e}")))?;
                self.added
                    .push(device_of(key_package.leaf_node().credential())?);
            }
            ProposalIn::Remove(remove) => self.removed_leaves.push(remove.removed().u32()),
            ProposalIn::SelfRemove => {
                let leaf = self
                    .sender_leaf
                    .ok_or_else(|| CryptoError::invalid("self removal by a non-member"))?;
                self.removed_leaves.push(leaf);
            }
            _ => {}
        }
        Ok(())
    }
}

fn read_u16(bytes: &mut &[u8]) -> Result<u16, CryptoError> {
    let Some((head, rest)) = bytes.split_first_chunk::<2>() else {
        return Err(CryptoError::invalid("truncated MLS message"));
    };
    *bytes = rest;
    Ok(u16::from_be_bytes(*head))
}
