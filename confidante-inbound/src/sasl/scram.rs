use std::{
    fmt::{Debug, Display, Formatter},
    marker::PhantomData,
    num::NonZero,
    str::FromStr,
};

use anyhow::{Error, bail};
use base64::prelude::*;
use confidante_core::xmpp::jid::Jid;
use digest::{Digest, FixedOutputReset, core_api::BlockSizeUser, generic_array::GenericArray};

use password_hash::{SaltString, rand_core::OsRng};
use rsasl::{
    callback::SessionCallback,
    config::SASLConfig,
    mechanisms::scram::{
        properties::ScramStoredPassword,
        tools::{derive_keys, hash_password},
    },
    property::AuthId,
};
use sha1::Sha1;
use sha2::Sha256;
use tokio::{
    select,
    sync::{mpsc, oneshot},
    task::{JoinHandle, spawn_blocking},
};

use crate::sasl::common::{AuthError, SaslValidation, SessionCallbackExt, authenticate};

use super::{MechanismNegotiatorResult, StoredPassword, StoredPasswordLookup};

const SCRAM_ITERATIONS: u32 = 4096;

#[derive(Debug)]
pub struct StoredPasswordScram<D> {
    iterations: NonZero<u32>,
    salt: Vec<u8>,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
    _digest_type: PhantomData<D>,
}

impl<D> StoredPassword for StoredPasswordScram<D>
where
    D: Digest + BlockSizeUser + FixedOutputReset + MechanismDigest + Clone + Sync,
{
    fn new(plaintext: &str) -> Result<Self, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let mut salted_password = GenericArray::default();
        // Derive the PBKDF2 key from the password and salt. This is the expensive part
        hash_password::<D>(
            plaintext.as_bytes(),
            SCRAM_ITERATIONS,
            &salt.as_str().as_bytes()[..],
            &mut salted_password,
        );
        let (client_key, server_key) = derive_keys::<D>(salted_password.as_slice());
        let stored_key = D::digest(client_key);

        Ok(Self {
            iterations: NonZero::new(SCRAM_ITERATIONS).expect("Iterations must be positive"),
            salt: salt.as_str().as_bytes().to_vec(),
            stored_key: stored_key.to_vec(),
            server_key: server_key.to_vec(),
            _digest_type: Default::default(),
        })
    }
}

impl<D> FromStr for StoredPasswordScram<D>
where
    D: Digest + BlockSizeUser + Clone + Sync, // TODO: minimize bounds
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('$').collect();

        if parts.len() != 6 {
            bail!("Invalid SCRAM password format.");
        }

        let iterations = parts[2].parse::<NonZero<u32>>()?;
        let salt = BASE64_STANDARD.decode(parts[3])?;
        let stored_key = BASE64_STANDARD.decode(parts[4])?;
        let server_key = BASE64_STANDARD.decode(parts[5])?;

        if iterations.get() != SCRAM_ITERATIONS {
            bail!("SCRAM iteration count outdated. Password must be reset.");
        }

        Ok(Self {
            iterations,
            salt,
            stored_key,
            server_key,
            _digest_type: Default::default(),
        })
    }
}

impl<D> Display for StoredPasswordScram<D>
where
    D: Digest + BlockSizeUser + MechanismDigest + Clone + Sync, // TODO: minimize bounds
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mechanism_name = D::mechanism_name(false);
        let iterations = self.iterations;
        let salt = BASE64_STANDARD.encode(&self.salt);
        let stored_key = BASE64_STANDARD.encode(&self.stored_key);
        let server_key = BASE64_STANDARD.encode(&self.server_key);

        write!(
            f,
            "${}${}${}${}${}",
            mechanism_name, iterations, salt, stored_key, server_key
        )
    }
}

trait MechanismDigest {
    fn mechanism_name(channel_binding: bool) -> &'static str;
    fn lookup_password<S>(
        jid: Jid,
        store: &S,
    ) -> impl std::future::Future<Output = Result<String, Error>> + Send
    where
        S: StoredPasswordLookup + Send + Sync;
}

impl MechanismDigest for Sha1 {
    fn mechanism_name(channel_binding: bool) -> &'static str {
        if channel_binding {
            "SCRAM-SHA-1-PLUS"
        } else {
            "SCRAM-SHA-1"
        }
    }

    fn lookup_password<S>(
        jid: Jid,
        store: &S,
    ) -> impl std::future::Future<Output = Result<String, Error>> + Send
    where
        S: StoredPasswordLookup + Send + Sync,
    {
        // TODO: check f we can make actores work with reference to moving the Jid here
        store.get_stored_password_scram_sha1(jid)
    }
}

impl MechanismDigest for Sha256 {
    fn mechanism_name(channel_binding: bool) -> &'static str {
        if channel_binding {
            "SCRAM-SHA-256-PLUS"
        } else {
            "SCRAM-SHA-256"
        }
    }

    fn lookup_password<S>(
        jid: Jid,
        store: &S,
    ) -> impl std::future::Future<Output = Result<String, Error>> + Send
    where
        S: StoredPasswordLookup + Send + Sync,
    {
        // TODO: check f we can make actores work with reference to moving the Jid here
        store.get_stored_password_scram_sha256(jid)
    }
}

struct ScramCallback<D> {
    tx: mpsc::Sender<(
        String,
        oneshot::Sender<Result<StoredPasswordScram<D>, Error>>,
    )>,
}

impl<D> ScramCallback<D> {
    pub fn new(
        tx: mpsc::Sender<(
            String,
            oneshot::Sender<Result<StoredPasswordScram<D>, Error>>,
        )>,
    ) -> Self {
        Self { tx }
    }
}

impl<D> SessionCallback for ScramCallback<D>
where
    D: Digest + BlockSizeUser + FixedOutputReset + MechanismDigest + Clone + Send + Sync, // TODO: minimize bounds
{
    fn callback(
        &self,
        _session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context,
        request: &mut rsasl::callback::Request,
    ) -> Result<(), rsasl::prelude::SessionError> {
        if let Some(authid) = context.get_ref::<AuthId>()
            && let Ok(stored_password) =
                self.lookup_stored_password::<StoredPasswordScram<D>>(authid, self.tx.clone())
        {
            let rsasl_stored_password = ScramStoredPassword::new(
                stored_password.iterations.get(),
                &stored_password.salt,
                &stored_password.stored_key,
                &stored_password.server_key,
            );
            request.satisfy::<ScramStoredPassword>(&rsasl_stored_password)?;
        }
        Ok(())
    }

    fn validate(
        &self,
        _session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context,
        validate: &mut rsasl::validate::Validate<'_>,
    ) -> Result<(), rsasl::validate::ValidationError> {
        validate.with::<SaslValidation, _>(|| {
            let auth_id =
                context
                    .get_ref::<AuthId>()
                    .map_or(
                        Err(AuthError::NoSuchUser),
                        |auth_id| Ok(auth_id.to_string()),
                    );

            Ok(auth_id)
        })?;

        Ok(())
    }
}

pub struct ScramNegotiator<S, D> {
    resolved_domain: String,
    input_tx: mpsc::Sender<Vec<u8>>,
    output_rx: mpsc::Receiver<MechanismNegotiatorResult>,
    password_lookup_rx: mpsc::Receiver<(
        String,
        oneshot::Sender<Result<StoredPasswordScram<D>, Error>>,
    )>,
    store: S,
    authenticator: JoinHandle<Result<String, Error>>,
}

impl<S, D> ScramNegotiator<S, D>
where
    S: StoredPasswordLookup + Send + Sync,
    D: Digest + BlockSizeUser + FixedOutputReset + MechanismDigest + Clone + Send + Sync + 'static, // TODO: minimize bounds
{
    pub fn new(resolved_domain: String, channel_binding: bool, store: S) -> Result<Self, Error> {
        // TODO: fix channel bounds
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(16);
        let (output_tx, output_rx) = mpsc::channel::<MechanismNegotiatorResult>(16);
        let (password_lookup_tx, password_lookup_rx) = mpsc::channel::<(
            String,
            oneshot::Sender<Result<StoredPasswordScram<D>, Error>>,
        )>(16);

        let config = SASLConfig::builder()
            .with_defaults()
            .with_callback(ScramCallback::new(password_lookup_tx))?;

        let mechname = D::mechanism_name(channel_binding).try_into()?;

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
                    let result = D::lookup_password(jid, &self.store).await;
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
