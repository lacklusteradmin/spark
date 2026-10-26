//! Denomination-separated blind signing keys. Public registries contain no secrets.
use spark_crypto::blind::{TryCryptoRng, TryRng};
use spark_crypto::{IssuerKey, IssuerPublic, KeySet, Token};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// Operating-system randomness, failing closed on entropy failure.
pub struct OsRandom;
impl TryRng for OsRandom {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(out).expect("OS entropy unavailable");
        Ok(())
    }
}
impl TryCryptoRng for OsRandom {}

/// Accepted public keys indexed by denomination. Clones share public updates.
#[derive(Clone, Default)]
pub struct PublicKeys(Arc<Mutex<BTreeMap<u8, Vec<IssuerPublic>>>>);
impl PublicKeys {
    /// An externally provisioned key for one denomination.
    pub fn single(class: u8, key: IssuerPublic) -> Self {
        let s = Self::default();
        s.0.lock().unwrap().insert(class, vec![key]);
        s
    }
    /// Export public keys for provisioning an independent verifier.
    pub fn keys(&self, class: u8) -> Vec<IssuerPublic> {
        self.0
            .lock()
            .unwrap()
            .get(&class)
            .cloned()
            .unwrap_or_default()
    }
    /// Verify only under keys provisioned for the claimed denomination.
    pub fn verify(&self, class: u8, token: &Token, message: &[u8]) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(&class)
            .is_some_and(|keys| spark_crypto::verify_any(keys, token, message).is_ok())
    }
}

/// Private signing keys. A key is never used for two denominations or purposes.
pub struct Mint {
    keys: BTreeMap<u8, KeySet>,
    public: PublicKeys,
    vault: Option<(crate::Db, String)>,
}
impl Mint {
    /// Provision the initial 1 MiB denomination.
    pub fn new(key: IssuerKey) -> Self {
        let public = PublicKeys::single(20, key.public());
        Self {
            keys: BTreeMap::from([(20, KeySet::new(key))]),
            public,
            vault: None,
        }
    }
    /// Load all denominations from a durable private vault, provisioning only missing keys.
    pub fn persisted(db: &crate::Db, purpose: &str, initial: Option<IssuerKey>) -> Self {
        let prefix = format!("mint/{purpose}/");
        let bytes = db.secret(&format!("{prefix}20"), || {
            KeySet::new(
                initial.unwrap_or_else(|| IssuerKey::generate(&mut OsRandom).expect("mint key")),
            )
            .secret_bytes()
            .unwrap()
        });
        let initial = KeySet::from_secret_bytes(&bytes).expect("corrupt mint vault");
        let mut keys = BTreeMap::from([(20, initial)]);
        for name in db.secret_names(&prefix) {
            let class: u8 = name[prefix.len()..].parse().expect("mint class");
            assert!((10..=40).contains(&class));
            keys.insert(
                class,
                KeySet::from_secret_bytes(&db.secret(&name, || unreachable!()))
                    .expect("corrupt mint vault"),
            );
        }
        let public = PublicKeys::default();
        for (&class, key) in &keys {
            public.0.lock().unwrap().insert(class, key.accepted());
        }
        Self {
            keys,
            public,
            vault: Some((db.clone(), prefix)),
        }
    }

    /// A separately generated mint, e.g. for refunds rather than storage.
    pub fn random() -> Self {
        Self::new(IssuerKey::generate(&mut OsRandom).expect("mint key generation"))
    }
    /// The public-only registry for a verifier in another trust domain.
    pub fn public_keys(&self) -> PublicKeys {
        self.public.clone()
    }
    /// Provision a denomination before use. Unknown/out-of-range classes fail closed.
    pub fn key(&mut self, class: u8) -> Option<&IssuerKey> {
        if !(10..=40).contains(&class) {
            return None;
        }
        if !self.keys.contains_key(&class) {
            let keyset = match &self.vault {
                Some((db, prefix)) => {
                    KeySet::from_secret_bytes(&db.secret(&format!("{prefix}{class}"), || {
                        KeySet::new(IssuerKey::generate(&mut OsRandom).expect("mint key"))
                            .secret_bytes()
                            .unwrap()
                    }))
                    .expect("mint vault")
                }
                None => {
                    KeySet::new(IssuerKey::generate(&mut OsRandom).expect("mint key generation"))
                }
            };
            self.public
                .0
                .lock()
                .unwrap()
                .insert(class, keyset.accepted());
            self.keys.insert(class, keyset);
        }
        Some(self.keys.get(&class).unwrap().signing())
    }
    /// Rotate an already provisioned denomination.
    pub fn replace(&mut self, class: u8, next: IssuerKey) {
        match self.keys.get_mut(&class) {
            Some(k) => k.rotate(next),
            None => {
                self.keys.insert(class, KeySet::new(next));
            }
        }
        if let Some((db, prefix)) = &self.vault {
            db.replace_secret(
                &format!("{prefix}{class}"),
                &self.keys[&class].secret_bytes().unwrap(),
            );
        }
        self.public
            .0
            .lock()
            .unwrap()
            .insert(class, self.keys[&class].accepted());
    }
}
