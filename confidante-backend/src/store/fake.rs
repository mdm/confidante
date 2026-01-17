use anyhow::{Error, anyhow};

use confidante_core::xmpp::jid::Jid;

use crate::store::StoredPasswordKind;

use super::StoreBackend;

#[derive(Default)]
pub struct FakeStoreBackend {
    pub stored_password_argon2: Option<String>,
    pub stored_password_scram_sha1: Option<String>,
    pub stored_password_scram_sha256: Option<String>,
}

impl StoreBackend for FakeStoreBackend {
    async fn add_user(
        &mut self,
        _jid: Jid,
        stored_password_argon2: String,
        stored_password_scram_sha1: String,
        stored_password_scram_sha256: String,
    ) -> Result<(), Error> {
        self.stored_password_argon2 = Some(stored_password_argon2);
        self.stored_password_scram_sha1 = Some(stored_password_scram_sha1);
        self.stored_password_scram_sha256 = Some(stored_password_scram_sha256);

        Ok(())
    }

    async fn remove_user(&mut self, _jid: Jid) -> Result<(), Error> {
        self.stored_password_argon2 = None;
        self.stored_password_scram_sha1 = None;
        self.stored_password_scram_sha256 = None;

        Ok(())
    }

    async fn get_stored_password(
        &self,
        _jid: Jid,
        kind: StoredPasswordKind,
    ) -> Result<String, Error> {
        match kind {
            StoredPasswordKind::Argon2 => self
                .stored_password_argon2
                .clone()
                .ok_or(anyhow!("No password stored for kind {:?}", kind)),
            StoredPasswordKind::ScramSha1 => self
                .stored_password_scram_sha1
                .clone()
                .ok_or(anyhow!("No password stored for kind {:?}", kind)),
            StoredPasswordKind::ScramSha256 => self
                .stored_password_scram_sha256
                .clone()
                .ok_or(anyhow!("No password stored for kind {:?}", kind)),
        }
    }

    async fn set_stored_password(
        &mut self,
        _jid: Jid,
        kind: StoredPasswordKind,
        stored_password: String,
    ) -> Result<(), Error> {
        match kind {
            StoredPasswordKind::Argon2 => {
                self.stored_password_argon2 = Some(stored_password);
            }
            StoredPasswordKind::ScramSha1 => {
                self.stored_password_scram_sha1 = Some(stored_password);
            }
            StoredPasswordKind::ScramSha256 => {
                self.stored_password_scram_sha256 = Some(stored_password);
            }
        }

        Ok(())
    }
}
