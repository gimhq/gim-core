//! The single place where gim's MLS group parameters are defined.

use openmls::prelude::{
    Capabilities, Ciphersuite, CredentialType, ExtensionType, MlsGroupCreateConfig,
    MlsGroupJoinConfig, SenderRatchetConfiguration, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
};

use crate::GIM_CREDENTIAL_TYPE;

/// Ciphersuite of every gim group and KeyPackage.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Application messages a receiver may skip ahead of within one sender
/// ratchet before older generations are dropped (out-of-order delivery).
pub const OUT_OF_ORDER_TOLERANCE: u32 = 32;

/// Largest generation gap accepted within one sender ratchet.
pub const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;

/// Past epochs whose message secrets are kept, so application messages sent
/// just before a commit still decrypt after it was merged.
pub const MAX_PAST_EPOCHS: usize = 3;

/// Ciphertexts are padded to a multiple of this many bytes.
pub const PADDING_SIZE: usize = 32;

/// Leaf node capabilities of every KeyPackage and group leaf. Lists the
/// LastResort extension so last-resort KeyPackages validate. Identities with
/// a gim credential support only [`GIM_CREDENTIAL_TYPE`]; legacy identities
/// keep the OpenMLS default (basic).
pub(crate) fn leaf_capabilities(gim_credential: bool) -> Capabilities {
    let gim = [CredentialType::Other(GIM_CREDENTIAL_TYPE)];
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::LastResort]),
        None,
        gim_credential.then_some(gim.as_slice()),
    )
}

/// Group configuration used when creating a group.
///
/// - Welcomes carry the ratchet tree, so they are self-contained.
/// - Wire format is pure ciphertext for both application and handshake
///   messages: commits and proposals are encrypted too, so the delivery
///   service learns nothing about membership changes from the payload. A
///   removed member can still decrypt the commit removing it because that
///   commit is encrypted under the epoch it was a member of.
pub(crate) fn group_create_config(capabilities: Capabilities) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            OUT_OF_ORDER_TOLERANCE,
            MAXIMUM_FORWARD_DISTANCE,
        ))
        .max_past_epochs(MAX_PAST_EPOCHS)
        .padding_size(PADDING_SIZE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

/// Group configuration used when joining from a Welcome; identical runtime
/// parameters to [`group_create_config`].
pub(crate) fn group_join_config() -> MlsGroupJoinConfig {
    group_create_config(leaf_capabilities(false))
        .join_config()
        .clone()
}
