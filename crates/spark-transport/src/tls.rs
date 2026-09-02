//! TLS, pinned to a key rather than delegated to the WebPKI.
//!
//! `docs/protocol.md` §6 says WebSocket over TLS. This is the TLS, and it wraps
//! the same `Read + Write` stream that SOCKS5 and WebSocket already compose over,
//! so it is an addition in one place and invisible everywhere else.
//!
//! # Why not the WebPKI
//!
//! The default answer would be to trust the same certificate authorities a browser
//! does. Spark should not, and the reason is not caution for its own sake:
//!
//! * A browser has to reach any site in the world, so it must trust a large set of
//!   issuers. Spark reaches a handful of endpoints it operates. The generality is
//!   pure cost.
//! * The WebPKI's guarantee is "*some* CA vouched for this name". There are on the
//!   order of a hundred and fifty of them, any one of which can be compelled. For
//!   software whose entire claim is that its operator cannot read your messages,
//!   "some CA said so" is a weaker statement than it sounds.
//! * A pin ships inside the client, and the client is built reproducibly (D4). A
//!   user can check that the binary they run contains the pin they expect. Nothing
//!   equivalent is true of a trust store they inherited.
//!
//! The cost is operational and real: rotating a server key means shipping a new
//! pin, and shipping one badly locks users out. Pinning the *public key* rather
//! than the certificate is what makes routine renewal free — a new certificate
//! over the same key keeps the same pin.
//!
//! Over Tor this is partly redundant: an onion address *is* a public key, so
//! reaching a `.onion` authenticates the endpoint without any of this. Pinning is
//! what covers the direct path, which D2's default mode uses for media.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::sync::Arc;

/// A pinned server identity: SHA-256 of the certificate's `SubjectPublicKeyInfo`.
///
/// The public key, not the certificate. A renewed certificate over the same key
/// has the same pin, so ordinary renewal does not require shipping anything.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Pin([u8; 32]);

impl Pin {
    /// The pin for a certificate.
    pub fn of(cert: &[u8]) -> Result<Self, TlsError> {
        use x509_cert::der::{Decode, Encode};
        let parsed =
            x509_cert::Certificate::from_der(cert).map_err(|_| TlsError::BadCertificate)?;
        let spki = parsed
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| TlsError::BadCertificate)?;
        Ok(Self(spark_crypto::sha256(&spki)))
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap raw bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Lowercase hex, which is how a pin is written down and shipped.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse the hex form.
    pub fn parse(s: &str) -> Result<Self, TlsError> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(TlsError::BadPin);
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| TlsError::BadPin)?;
        }
        Ok(Self(out))
    }
}

/// Accepts exactly the servers whose public key is pinned.
#[derive(Debug)]
struct Pinned {
    pins: Vec<Pin>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Intermediates, the server name and validity dates are all deliberately
        // unused. A pin is a statement about *which key*, and a chain that led to
        // a different key would be a different server whatever it was named or
        // when it expired. Checking a name in addition would only add a way to
        // fail; it could not add a way to be safe that the pin does not already
        // provide.
        let seen = Pin::of(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Constant-time over the whole set: which pin matched is not something a
        // timing difference should reveal.
        use subtle::ConstantTimeEq;
        let mut ok = subtle::Choice::from(0u8);
        for p in &self.pins {
            ok |= seen.as_bytes().ct_eq(p.as_bytes());
        }
        if bool::from(ok) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Delegated, not reimplemented. Pinning replaces *which* key to trust; it
        // does not replace checking that the peer holds it, and that check is the
        // part where a mistake is silent.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A client that will speak only to the pinned servers.
pub fn client_config(pins: Vec<Pin>) -> Result<ClientConfig, TlsError> {
    if pins.is_empty() {
        // An empty pin set would accept nothing, which is safe, or — if someone
        // "fixed" it later by falling back to the WebPKI — everything. Refusing
        // here removes the temptation.
        return Err(TlsError::NoPins);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Config)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { pins, provider }))
        .with_no_client_auth();
    // Sessions are not resumed across connections. A resumption ticket is a
    // linkable token the server hands out, and every request already gets its own
    // Tor circuit for the same reason.
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(cfg)
}

/// A server presenting `cert` and holding `key`.
pub fn server_config(cert: Vec<u8>, key: PrivateKeyDer<'static>) -> Result<ServerConfig, TlsError> {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Config)?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert)], key)
        .map_err(|_| TlsError::Config)
}

/// Why TLS could not be set up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsError {
    /// The certificate would not parse.
    BadCertificate,
    /// A pin is not 64 hex characters.
    BadPin,
    /// No pins were supplied, so nothing could ever be trusted.
    NoPins,
    /// The TLS configuration was rejected.
    Config,
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadCertificate => f.write_str("the server's certificate did not parse"),
            Self::BadPin => f.write_str("a pin must be 64 hex characters"),
            Self::NoPins => f.write_str("no server pins were supplied"),
            Self::Config => f.write_str("the TLS configuration was rejected"),
        }
    }
}
impl core::error::Error for TlsError {}
