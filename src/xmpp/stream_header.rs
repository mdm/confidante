use base64::prelude::*;
use rand::{RngCore, SeedableRng};

use super::jid::Jid;

#[derive(Debug, Clone)]
pub struct StreamId(String);

impl StreamId {
    pub fn new() -> Self {
        let id = Self::generate_id();
        Self(id)
    }

    fn generate_id() -> String {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy(); // TODO: use UUID instead?
        let mut id_raw = [0u8; 16];
        rng.fill_bytes(&mut id_raw);
        let id_encoded = BASE64_STANDARD.encode(id_raw);

        id_encoded
    }
}

#[derive(Debug)]
pub struct LanguageTag(pub String); // TODO: make inner field private

#[derive(Debug)]
pub struct StreamHeader {
    pub from: Option<Jid>,
    pub to: Option<Jid>,
    pub id: Option<StreamId>,
    pub language: Option<LanguageTag>,
    // TODO: add version
}
