// A "convenience" constructor that would look entirely reasonable in review:
// restoring an identity from a device backup so users do not have to retype 24
// words. It is also, precisely, the recovery path Spark F2 says cannot exist —
// "any recovery path available to you would also be available to an attacker".
impl Identity {
    pub fn from_mnemonic(m: &Mnemonic) -> Self { Self::from_seed(&m.to_seed()) }
    pub fn from_seed(seed: &Seed) -> Self { todo!() }
    pub fn from_device_backup(blob: &[u8]) -> Result<Self, Error> { todo!() }
}
