use std::{fmt::Display, str::FromStr};

use anyhow::Error;
use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHashString, PasswordHasher, SaltString, rand_core::OsRng},
};
use confidante_core::xmpp::jid::Jid;
use rsasl::{
    callback::SessionCallback,
    config::SASLConfig,
    property::{AuthId, AuthzId, Password},
};
use tokio::{
    select,
    sync::{mpsc, oneshot},
    task::{JoinHandle, spawn_blocking},
};

use crate::sasl::{
    MechanismNegotiatorResult, StoredPasswordLookup,
    common::{AuthError, SaslValidation, SessionCallbackExt, authenticate},
};

use super::StoredPassword;

#[derive(Debug)]
pub struct StoredPasswordArgon2 {
    pub hash: PasswordHashString,
}

impl StoredPassword for StoredPasswordArgon2 {
    fn new(plaintext: &str) -> Result<Self, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(plaintext.as_bytes(), &salt)?.into();
        Ok(Self { hash })
    }
}

impl FromStr for StoredPasswordArgon2 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hash = PasswordHashString::new(s)?;
        Ok(Self { hash })
    }
}

impl Display for StoredPasswordArgon2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hash)
    }
}

type StoredPasswordSender = oneshot::Sender<Result<StoredPasswordArgon2, Error>>;

struct PlainCallback {
    tx: mpsc::Sender<(String, StoredPasswordSender)>,
}

impl PlainCallback {
    pub fn new(tx: mpsc::Sender<(String, StoredPasswordSender)>) -> Self {
        Self { tx }
    }
}

impl SessionCallback for PlainCallback {
    fn validate(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context,
        validate: &mut rsasl::validate::Validate<'_>,
    ) -> Result<(), rsasl::validate::ValidationError> {
        if session_data.mechanism().mechanism != "PLAIN" {
            return Ok(());
        }

        validate.with::<SaslValidation, _>(|| {
            let authzid = context
                .get_ref::<AuthzId>()
                .filter(|authzid| !authzid.is_empty());
            let Some(authid) = context.get_ref::<AuthId>() else {
                return Ok(Err(AuthError::NoSuchUser));
            };
            let Some(password) = context.get_ref::<Password>() else {
                return Ok(Err(AuthError::PasswordIncorrect));
            };

            println!(
                "SIMPLE VALIDATION for (authzid: {:?}, authid: {:?}, password: {:?})",
                authzid,
                authid,
                std::str::from_utf8(password)
            );

            if !(authzid.is_none() || authzid == Some(authid)) {
                Ok(Err(AuthError::AuthzBad))
            } else if let Ok(stored_password) =
                self.lookup_stored_password::<StoredPasswordArgon2>(authid, self.tx.clone())
                && let Ok(stored_password) = PasswordHash::new(stored_password.hash.as_str())
            {
                let argon2 = Argon2::default();
                match argon2.verify_password(password, &stored_password) {
                    Ok(_) => Ok(Ok(authid.to_string())),
                    Err(_) => Ok(Err(AuthError::PasswordIncorrect)),
                }
            } else {
                Ok(Err(AuthError::NoSuchUser))
            }
        })?;

        Ok(())
    }
}

pub(super) struct PlainNegotiator<S> {
    resolved_domain: String,
    input_tx: mpsc::Sender<Vec<u8>>,
    output_rx: mpsc::Receiver<MechanismNegotiatorResult>,
    password_lookup_rx: mpsc::Receiver<(String, StoredPasswordSender)>,
    store: S,
    authenticator: JoinHandle<Result<String, Error>>,
}

impl<S> PlainNegotiator<S>
where
    S: StoredPasswordLookup,
{
    pub fn new(resolved_domain: String, store: S) -> Result<Self, Error> {
        // TODO: fix channel bounds
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(16);
        let (output_tx, output_rx) = mpsc::channel::<MechanismNegotiatorResult>(16);
        let (password_lookup_tx, password_lookup_rx) =
            mpsc::channel::<(String, oneshot::Sender<Result<StoredPasswordArgon2, Error>>)>(16);

        let config = SASLConfig::builder()
            .with_defaults()
            .with_callback(PlainCallback::new(password_lookup_tx))?;

        let mechname = "PLAIN".try_into()?;

        let authenticator =
            spawn_blocking(move || authenticate(config, mechname, input_rx, output_tx));

        Ok(Self {
            resolved_domain,
            input_tx,
            output_rx,
            password_lookup_rx,
            store,
            authenticator,
        })
    }

    pub async fn process(&mut self, payload: Vec<u8>) -> MechanismNegotiatorResult {
        self.input_tx.send(payload).await.unwrap();

        loop {
            select! {
                Some(output) = self.output_rx.recv() => {
                    return output;
                }
                Some((authid, response_tx)) = self.password_lookup_rx.recv() => {
                    let jid = Jid::new(Some(authid), self.resolved_domain.clone(), None);
                    let result = self.store.get_stored_password_argon2(jid).await;
                    let result = result.and_then(|stored_password| stored_password.parse());
                    let _ = response_tx.send(result);
                }
            }
        }
    }

    pub async fn authentication_id(self) -> Result<String, Error> {
        self.authenticator.await?
    }
}
