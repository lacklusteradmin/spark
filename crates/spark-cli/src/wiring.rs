//! The one place the client meets real service instances.
//!
//! `spark-client` talks to [`spark_client::Services`], a trait. This is the
//! implementation that runs all three services in this process, which is what
//! makes the CLI a verification harness rather than a demo: the client exercises
//! the same code paths a networked one will, against the same server logic that
//! gate 5 audits.
//!
//! What is *not* here is a network. `docs/protocol.md` §6 specifies WebSocket over
//! TLS, and `spark-transport` has the routing and the SOCKS5 but not the framing.
//! A second implementation of this trait is the remaining work.

use spark_client::{
    Auth, Class, ContentService, IssuerService, KeyringService, ServiceError, Services,
};
use spark_crypto::{IssuerKey, Secret, Token, TokenClaim};
use spark_store::Db;

use spark_content_server as content;
use spark_issuer as issuer;
use spark_keyring_server as keyring;

/// All three services, in one process.
pub struct Local {
    keyring: keyring::Keyring,
    content: content::Content,
    issuer: issuer::Issuer,
}

impl Local {
    /// Stand up a fresh deployment.
    pub fn new(token_key: IssuerKey, voucher_key: IssuerKey, server_secret: [u8; 32]) -> Self {
        let keyring = keyring::Keyring::new(Db::new(), Secret::new(server_secret), token_key);
        // The content service is given only the *public* halves. It cannot mint a
        // token, and so cannot forge the evidence that someone paid.
        let content = content::Content::with_keys(Db::new(), keyring.accepted_keys());
        let issuer = issuer::Issuer::new(Db::new(), voucher_key);
        Self {
            keyring,
            content,
            issuer,
        }
    }

    /// Advance the keyring service's clock, which it never reads for itself.
    pub fn set_minute(&self, m: u64) {
        self.keyring.set_minute(m);
    }

    /// Everything the services hold, for the audit the CLI prints.
    pub fn stored_bytes(&self) -> (usize, usize, usize) {
        (
            self.keyring.db().all_bytes().len(),
            self.content.db().all_bytes().len(),
            self.issuer.db().all_bytes().len(),
        )
    }

    /// Whether any of the three holds this needle. Used to demonstrate that they
    /// do not hold plaintext.
    pub fn holds(&self, needle: &[u8]) -> bool {
        let has = |b: Vec<u8>| b.windows(needle.len()).any(|w| w == needle);
        !needle.is_empty()
            && (has(self.keyring.db().all_bytes())
                || has(self.content.db().all_bytes())
                || has(self.issuer.db().all_bytes()))
    }

    /// How many chunks the content store holds.
    pub fn chunk_count(&self) -> usize {
        self.content.db().keys(content::T_CHUNK).len()
    }
}

fn to_auth(a: &Auth) -> keyring::Auth {
    keyring::Auth {
        addr: a.addr,
        key: a.key,
        sig: a.sig,
    }
}

impl KeyringService for Local {
    fn challenge(&self, addr: &[u8; 32]) -> [u8; 32] {
        self.keyring.challenge(addr)
    }
    fn snapshot(&self, auth: &Auth) -> Result<Option<Vec<u8>>, ServiceError> {
        match self
            .keyring
            .handle(keyring::Request::GetSnapshot(to_auth(auth)))
        {
            keyring::Response::Snapshot(s) => Ok(s),
            _ => Err(ServiceError::Refused),
        }
    }
    fn deltas(&self, auth: &Auth) -> Result<Vec<Vec<u8>>, ServiceError> {
        match self
            .keyring
            .handle(keyring::Request::GetDeltas(to_auth(auth)))
        {
            keyring::Response::Deltas(d) => Ok(d),
            _ => Err(ServiceError::Refused),
        }
    }
    fn put_delta(&self, auth: &Auth, chunk: &[u8]) -> Result<(), ServiceError> {
        match self
            .keyring
            .handle(keyring::Request::PutDelta(to_auth(auth), chunk.to_vec()))
        {
            keyring::Response::Appended { .. } => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
    fn put_snapshot(&self, auth: &Auth, chunk: &[u8]) -> Result<(), ServiceError> {
        match self
            .keyring
            .handle(keyring::Request::PutSnapshot(to_auth(auth), chunk.to_vec()))
        {
            keyring::Response::SnapshotWritten => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
    fn issuer_key(&self) -> Result<Vec<u8>, ServiceError> {
        match self.keyring.handle(keyring::Request::GetIssuerKey) {
            keyring::Response::IssuerKey(d) => Ok(d),
            _ => Err(ServiceError::Refused),
        }
    }
    fn withdraw(
        &self,
        auth: &Auth,
        blinded: &[Vec<u8>],
        size_class: u8,
    ) -> Result<Vec<Vec<u8>>, ServiceError> {
        match self.keyring.handle(keyring::Request::WithdrawTokens {
            auth: to_auth(auth),
            blinded: blinded.to_vec(),
            size_class,
        }) {
            keyring::Response::Tokens(t) => Ok(t),
            _ => Err(ServiceError::Refused),
        }
    }
    fn put_request(&self, addr: &[u8; 32], blob: &[u8], token: &[u8]) -> Result<(), ServiceError> {
        match self.keyring.handle(keyring::Request::PutRequest {
            addr: *addr,
            blob: blob.to_vec(),
            token: token.to_vec(),
        }) {
            keyring::Response::RequestTaken => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
    fn requests(&self, auth: &Auth) -> Result<Vec<(u32, Vec<u8>)>, ServiceError> {
        match self
            .keyring
            .handle(keyring::Request::GetRequests(to_auth(auth)))
        {
            keyring::Response::Requests(r) => Ok(r),
            _ => Err(ServiceError::Refused),
        }
    }
    fn drop_request(&self, auth: &Auth, index: u32) -> Result<(), ServiceError> {
        match self
            .keyring
            .handle(keyring::Request::DropRequest(to_auth(auth), index))
        {
            keyring::Response::RequestDropped => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
}

impl ContentService for Local {
    /// The traffic class is ignored: there is no network here to route over. It
    /// is still in the signature so that this and the networked implementation
    /// present the same surface to the client, which is what makes running the
    /// same tests against both meaningful.
    fn put(
        &self,
        _class: Class,
        name: &[u8; 32],
        chunk: &[u8],
        claim: TokenClaim,
        token: &Token,
    ) -> Result<[u8; 32], ServiceError> {
        match self.content.handle(content::Request::Put {
            name: *name,
            chunk: chunk.to_vec(),
            claim,
            token: token.clone(),
        }) {
            content::Response::Stored { receipt } => Ok(receipt),
            _ => Err(ServiceError::Refused),
        }
    }
    fn get(&self, _class: Class, name: &[u8; 32]) -> Result<Option<Vec<u8>>, ServiceError> {
        match self.content.handle(content::Request::Get { name: *name }) {
            content::Response::Chunk(b) => Ok(Some(b)),
            content::Response::Refused(content::Refusal::NotFound) => Ok(None),
            _ => Err(ServiceError::Refused),
        }
    }
    fn release(
        &self,
        _class: Class,
        name: &[u8; 32],
        receipt: &[u8; 32],
    ) -> Result<Vec<u8>, ServiceError> {
        match self.content.handle(content::Request::Release {
            name: *name,
            receipt: *receipt,
        }) {
            content::Response::Released { voucher, .. } => Ok(voucher),
            _ => Err(ServiceError::Refused),
        }
    }
}

impl IssuerService for Local {
    fn resolve(&self, name: &str, today: u32) -> Result<Option<[u8; 64]>, ServiceError> {
        match self
            .issuer
            .handle(issuer::Request::Resolve(name.to_string(), today))
        {
            issuer::Response::Resolved(k) => Ok(k),
            _ => Err(ServiceError::Refused),
        }
    }
}

impl Services for Local {
    fn keyring(&self) -> &dyn KeyringService {
        self
    }
    fn content(&self) -> &dyn ContentService {
        self
    }
    fn issuer(&self) -> &dyn IssuerService {
        self
    }
}
