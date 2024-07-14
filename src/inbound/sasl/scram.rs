use std::{
    fmt::{Debug, Display, Formatter},
    num::NonZero,
    str::FromStr,
};

use anyhow::{anyhow, Error};
use digest::{core_api::BlockSizeUser, Digest};
use password_hash::{rand_core::OsRng, SaltString};
use scram_rs::{
    async_trait, scram_async::AsyncScramServer, AsyncScramAuthServer, AsyncScramCbHelper,
    ScramHashing, ScramNonce, ScramPassword, ScramResult, ScramResultServer, ScramSha1Ring,
    SCRAM_TYPES,
};
use sha1::Sha1;

use crate::{services::store::StoreHandle, xmpp::jid::Jid};

use super::{MechanismNegotiator, MechanismNegotiatorResult, StoredPassword};

#[derive(Debug)]
pub struct StoredPasswordScram<H>
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
        let iterations = NonZero::new(4096).expect("Iterations must be positive"); // TODO: drastically increase this
        let salt = SaltString::generate(&mut OsRng);
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
    type Err = password_hash::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<H> Display for StoredPasswordScram<H>
where
    H: ScramHashing,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

pub struct ScramSha1Negotiator {
    resolved_domain: String,
    server: AsyncScramServer<ScramSha1Ring, ScramAuthHelper, ScramAuthHelper>,
}

impl MechanismNegotiator for ScramSha1Negotiator {
    fn new(resolved_domain: String, store: StoreHandle) -> Result<Self, Error> {
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
                ))
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
                let username = self.server.get_auth_username().cloned(); // TODO: error out if username is not set at this point
                let jid = Jid::new(username, self.resolved_domain.clone(), None);
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
struct ScramAuthHelper {
    // TODO: split into two structs, for user lookup and channel binding
    resolved_domain: String,
    store: StoreHandle,
}

#[async_trait]
impl AsyncScramCbHelper for ScramAuthHelper {}

#[async_trait]
impl AsyncScramAuthServer<ScramSha1Ring> for ScramAuthHelper {
    async fn get_password_for_user(&self, username: &str) -> ScramResult<ScramPassword> {
        let jid = Jid::new(
            Some(username.to_string()),
            self.resolved_domain.clone(),
            None,
        );
        let stored_password = self.store.get_stored_password_scram_sha1(jid).await;

        match stored_password {
            Some(stored_password) => match stored_password.stored_password {
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
            None => ScramPassword::not_found::<ScramSha1Ring>(),
        }
    }
}
