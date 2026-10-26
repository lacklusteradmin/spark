//! Server identity for a deployment.
//!
//! A self-signed certificate, because the client pins the *key* and does not
//! consult a certificate authority (see `spark_transport::tls`). Nothing an
//! authority would attest to is used, so paying one to attest to it would buy
//! nothing.
//!
//! Verification harnesses generate ephemeral identities; `serve` persists its
//! certificate and key together in its private SQLite vault. Pins survive restart.

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

/// Reopen the same TLS identity after restart. The vault is operator-only.
pub fn persistent(db: &spark_store::Db, name: &str) -> Result<Identity, String> {
    let bytes = db.secret("tls-identity", || {
        let id = generate(name).expect("TLS identity generation");
        let mut bytes = (id.cert.len() as u32).to_be_bytes().to_vec();
        bytes.extend(id.cert);
        bytes.extend(id.key);
        bytes
    });
    if bytes.len() < 4 {
        return Err("corrupt TLS vault".into());
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let cert = bytes
        .get(4..4usize.checked_add(n).ok_or("TLS length")?)
        .ok_or("TLS certificate length")?
        .to_vec();
    let key = bytes[4 + n..].to_vec();
    let pin = Pin::of(&cert).map_err(|e| e.to_string())?;
    Ok(Identity { cert, key, pin })
}
