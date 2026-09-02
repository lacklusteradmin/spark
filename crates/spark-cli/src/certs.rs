//! Server identity for a deployment.
//!
//! A self-signed certificate, because the client pins the *key* and does not
//! consult a certificate authority (see `spark_transport::tls`). Nothing an
//! authority would attest to is used, so paying one to attest to it would buy
//! nothing.
//!
//! Generated fresh here, which is right for a verification harness and wrong for
//! a deployment: a real one keeps its key across restarts, or every restart
//! invalidates every pin in every client. That is the operational cost of pinning,
//! and it is the reason the pin is of the public key rather than the certificate —
//! the certificate can be reissued freely as long as the key stays.

use spark_transport::Pin;

/// A generated server identity.
pub struct Identity {
    /// The certificate, DER-encoded.
    pub cert: Vec<u8>,
    /// The private key, DER-encoded.
    pub key: Vec<u8>,
    /// What a client must pin to reach this server.
    pub pin: Pin,
}

/// Generate a self-signed identity for `name`.
pub fn generate(name: &str) -> Result<Identity, String> {
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params =
        rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;

    let der = cert.der().to_vec();
    let pin = Pin::of(&der).map_err(|e| e.to_string())?;
    Ok(Identity {
        cert: der,
        key: key.serialize_der(),
        pin,
    })
}
