//! Device link handles: the new device's link offer and the old device's
//! pending approval. Both only carry state between `GimClient` calls.

/// A link offer of a new device: show [`Self::qr_string`] as a QR code,
/// then pass it to `GimClient::wait_link`. Accepts a single bundle; start a
/// new one after a failed `wait_link`.
#[derive(uniffi::Object)]
pub struct LinkSession(pub(crate) gim_sdk::LinkSession);

#[uniffi::export]
impl LinkSession {
    /// The string to encode in the QR code the old device scans.
    pub fn qr_string(&self) -> String {
        self.0.qr_string.clone()
    }
}

/// A link approved on the old device: show [`Self::sas`], then pass it to
/// `GimClient::confirm_approval`.
#[derive(uniffi::Object)]
pub struct PendingApproval(pub(crate) gim_sdk::PendingApproval);

#[uniffi::export]
impl PendingApproval {
    /// Six-digit short authentication string, `"123 456"`.
    pub fn sas(&self) -> String {
        self.0.sas.to_string()
    }

    /// The new device.
    pub fn device_id(&self) -> String {
        self.0.device.device_id.to_string()
    }
}
