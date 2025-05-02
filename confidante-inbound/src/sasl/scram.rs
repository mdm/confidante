use std::{
    fmt::{Debug, Display, Formatter},
    num::NonZero,
    str::FromStr,
};

use anyhow::{Error, anyhow, bail};
use base64::prelude::*;
use password_hash::{SaltString, rand_core::OsRng};
use scram_rs::{
    AsyncScramAuthServer, AsyncScramCbHelper, SCRAM_TYPES, ScramHashing, ScramKey, ScramNonce,
    ScramPassword, ScramResult, ScramResultServer, ScramSha1Ring, ScramSha256Ring, async_trait,
    scram_async::AsyncScramServer,
};

use confidante_core::xmpp::jid::Jid;

use super::{MechanismNegotiator, MechanismNegotiatorResult, StoredPassword, StoredPasswordLookup};

#[derive(Debug)]
struct StoredPasswordScram<H>
where
    H: ScramHashing,
{
    stored_password: ScramPassword,
    _hash_type: std::marker::PhantomData<H>,
}

impl<H> StoredPassword for StoredPasswordScram<H>
where
    H: ScramHashing,
{
    fn new(plaintext: &str) -> Result<Self, Error> {
        let iterations = NonZero::new(4096).expect("Iterations must be positive");
        let salt = SaltString::generate(&mut OsRng);
        dbg!(&salt);
        let stored_password = ScramPassword::salt_password_with_params::<&str, H>(
            plaintext,
            Some(salt.as_str().as_bytes().to_vec()),
            Some(iterations),
            None,
        )
        .map_err(|err| anyhow!("Could not create SCRAM password:").context(err))?;

        Ok(Self {
            stored_password,
            _hash_type: Default::default(),
        })
    }
}

impl<H> FromStr for StoredPasswordScram<H>
where
    H: ScramHashing,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('$').collect();

        if parts.len() != 7 {
            bail!("Invalid SCRAM password format");
        }

        dbg!(&parts);
        let iterations = parts[2].parse::<NonZero<u32>>()?;
        let salt_base64 = parts[3].to_string();
        dbg!(&salt_base64);
        let salted_hashed_password = BASE64_STANDARD.decode(parts[4])?;
        let client_key = BASE64_STANDARD.decode(parts[5])?;
        let server_key = BASE64_STANDARD.decode(parts[6])?;
        let mut scram_keys = ScramKey::new();
        scram_keys.set_client_key(client_key);
        scram_keys.set_server_key(server_key);

        Ok(Self {
            stored_password: ScramPassword::found_secret_password(
                salted_hashed_password,
                salt_base64,
                iterations,
                Some(scram_keys),
            ),
            _hash_type: Default::default(),
        })
    }
}

impl<H> Display for StoredPasswordScram<H>
where
    H: ScramHashing,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let salted_hashed_password = self.stored_password.get_salted_hashed_password();
        let salt_base64 = self.stored_password.get_salt_base64();
        let iterations = self.stored_password.get_iterations();
        let scram_keys = self.stored_password.get_scram_keys();

        let salted_hashed_password = BASE64_STANDARD.encode(salted_hashed_password);
        let client_key = BASE64_STANDARD.encode(scram_keys.get_clinet_key());
        let server_key = BASE64_STANDARD.encode(scram_keys.get_server_key());

        write!(
            f,
            "$SCRAM-SHA-1${}${}${}${}${}",
            iterations, salt_base64, salted_hashed_password, client_key, server_key
        )
    }
}

pub struct StoredPasswordScramSha1 {
    inner: StoredPasswordScram<ScramSha1Ring>,
}

impl StoredPassword for StoredPasswordScramSha1 {
    fn new(plaintext: &str) -> Result<Self, Error> {
        let inner = StoredPasswordScram::<ScramSha1Ring>::new(plaintext)?;
        Ok(Self { inner })
    }
}

impl FromStr for StoredPasswordScramSha1 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = StoredPasswordScram::<ScramSha1Ring>::from_str(s)?;
        Ok(Self { inner })
    }
}

impl Display for StoredPasswordScramSha1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

pub struct StoredPasswordScramSha256 {
    inner: StoredPasswordScram<ScramSha256Ring>,
}

impl StoredPassword for StoredPasswordScramSha256 {
    fn new(plaintext: &str) -> Result<Self, Error> {
        let inner = StoredPasswordScram::<ScramSha256Ring>::new(plaintext)?;
        Ok(Self { inner })
    }
}

impl FromStr for StoredPasswordScramSha256 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = StoredPasswordScram::<ScramSha256Ring>::from_str(s)?;
        Ok(Self { inner })
    }
}

impl Display for StoredPasswordScramSha256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

pub struct ScramSha1Negotiator<S>
where
    S: StoredPasswordLookup + Send + Sync,
{
    resolved_domain: String,
    server: AsyncScramServer<ScramSha1Ring, ScramAuthHelper<S>, ScramAuthHelper<S>>,
}

impl<S> MechanismNegotiator<S> for ScramSha1Negotiator<S>
where
    S: StoredPasswordLookup + Send + Sync,
{
    fn new(resolved_domain: String, store: S) -> Result<Self, Error> {
        let helper = ScramAuthHelper {
            resolved_domain: resolved_domain.clone(),
            store,
        };

        let scram_type = SCRAM_TYPES.get_scramtype("SCRAM-SHA-1").unwrap();
        let server = AsyncScramServer::new(helper.clone(), helper, ScramNonce::none(), scram_type)
            .map_err(|_err| anyhow!("Could not initialize SCRAM server"))?;

        Ok(Self {
            resolved_domain,
            server,
        })
    }

    async fn process(&mut self, payload: Vec<u8>) -> MechanismNegotiatorResult {
        let payload = match std::str::from_utf8(&payload) {
            Ok(payload) => payload,
            Err(_) => {
                return MechanismNegotiatorResult::Failure(anyhow!(
                    "Could not parse payload as UTF-8"
                ));
            }
        };
        let step_result = self.server.parse_response(payload).await;

        match step_result {
            ScramResultServer::Data(challenge) => {
                MechanismNegotiatorResult::Challenge(challenge.into_bytes())
            }
            ScramResultServer::Error(err) => {
                MechanismNegotiatorResult::Failure(anyhow!(err.message.clone()).context(err))
            }
            ScramResultServer::Final(additional_data) => {
                let username = self.server.get_auth_username().cloned().unwrap();
                let jid = Jid::new(Some(username), self.resolved_domain.clone(), None);
                let additional_data = if additional_data.is_empty() {
                    None
                } else {
                    Some(additional_data.into_bytes())
                };
                MechanismNegotiatorResult::Success(jid, additional_data)
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ScramAuthHelper<S>
where
    S: StoredPasswordLookup + Sync + Send,
{
    resolved_domain: String,
    store: S,
}

#[async_trait]
impl<S> AsyncScramCbHelper for ScramAuthHelper<S> where S: StoredPasswordLookup + Sync + Send {}

#[async_trait]
impl<S> AsyncScramAuthServer<ScramSha1Ring> for ScramAuthHelper<S>
where
    S: StoredPasswordLookup + Sync + Send,
{
    async fn get_password_for_user(&self, username: &str) -> ScramResult<ScramPassword> {
        let jid = Jid::new(
            Some(username.to_string()),
            self.resolved_domain.clone(),
            None,
        );
        dbg!(&jid);
        let stored_password = self.store.get_stored_password_scram_sha1(jid).await;
        dbg!(&stored_password);

        let stored_password = stored_password
            .and_then(|password| password.parse::<StoredPasswordScram<ScramSha1Ring>>());

        match stored_password {
            Ok(stored_password) => match stored_password.stored_password {
                ScramPassword::UserPasswordData {
                    salted_hashed_password,
                    salt_b64,
                    iterations,
                    scram_keys,
                } => Ok(ScramPassword::found_secret_password(
                    salted_hashed_password,
                    salt_b64,
                    iterations,
                    Some(scram_keys),
                )),
                _ => ScramPassword::not_found::<ScramSha1Ring>(),
            },
            Err(_) => ScramPassword::not_found::<ScramSha1Ring>(),
        }
    }
}
