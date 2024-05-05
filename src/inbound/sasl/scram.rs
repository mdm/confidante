use std::io::Cursor;

use anyhow::{anyhow, Error};
use digest::{generic_array::GenericArray, Digest, Output};
use rsasl::{
    callback::{Context, Request, SessionCallback, SessionData},
    config::SASLConfig,
    mechanisms::scram::{self, properties::ScramStoredPassword},
    mechname::Mechname,
    prelude::{SASLServer, Session, SessionError, State},
    property::{AuthId, Password},
    validate::{Validate, Validation, ValidationError},
};
use sha1::Sha1;

use crate::xmpp::jid::Jid;

use super::{MechanismNegotiator, MechanismNegotiatorResult};

pub struct ScramSha1Negotiator {
    sasl_session: Session<SaslValidation>,
}

impl MechanismNegotiator for ScramSha1Negotiator {
    fn with_credentials() -> Result<Self, Error> {
        let plain_password = b"password";
        let salt = b"bad salt";
        let mut hashed_password = GenericArray::default();
        // Derive the PBKDF2 key from the password and salt. This is the expensive part
        // TODO: do we need to off-load this to a separate thread? benchmark!
        scram::tools::hash_password::<Sha1>(plain_password, 4096, &salt[..], &mut hashed_password);
        let (client_key, server_key) =
            scram::tools::derive_keys::<Sha1>(hashed_password.as_slice());
        let stored_key = Sha1::digest(client_key);

        let sasl_config = SASLConfig::builder()
            .with_defaults()
            .with_callback(SaslCallback {
                salt,
                server_key,
                stored_key,
            })?;

        let sasl = SASLServer::<SaslValidation>::new(sasl_config);

        let sasl_session = sasl.start_suggested(Mechname::parse(b"SCRAM-SHA-1").unwrap())?;

        Ok(Self { sasl_session })
    }

    fn process(&mut self, payload: Vec<u8>) -> MechanismNegotiatorResult {
        let mut do_last_step = false;
        loop {
            let mut out = Cursor::new(Vec::new());
            let step_result = if payload.is_empty() || do_last_step {
                match self.sasl_session.step(None, &mut out) {
                    Ok(step_result) => step_result,
                    Err(e) => return MechanismNegotiatorResult::Failure(e.into()),
                }
            } else {
                match self.sasl_session.step(Some(&payload), &mut out) {
                    Ok(step_result) => step_result,
                    Err(e) => return MechanismNegotiatorResult::Failure(e.into()),
                }
            };

            match step_result {
                (State::Running, Some(_len)) => {
                    return MechanismNegotiatorResult::Challenge(out.into_inner());
                }
                (State::Running, None) => {
                    // If the other side indicates a completed authentication and
                    // sends no further authentication data but the last call to
                    // step returned State::Running you MUST call step a final time
                    // with a None input! This is critical to upholding all security
                    // guarantees that different mechanisms offer.
                    do_last_step = true;
                }
                (State::Finished, additional_data) => {
                    // TODO: Compare identity to stream header

                    let Some(Ok(entity)) = self.sasl_session.validation() else {
                        return MechanismNegotiatorResult::Failure(anyhow!(
                            "SASL validation failed"
                        ));
                    };

                    let jid = Jid::new(Some(entity), "localhost".to_string(), None);

                    return MechanismNegotiatorResult::Success(
                        jid,
                        additional_data.map(|_| out.into_inner()),
                    );
                }
            }
        }
    }
}

struct SaslValidation;
impl Validation for SaslValidation {
    type Value = Result<String, Error>;
}

struct SaslCallback {
    stored_key: Output<Sha1>,
    server_key: Output<Sha1>,
    salt: &'static [u8],
}

impl SessionCallback for SaslCallback {
    fn callback(
        &self,
        _session_data: &SessionData,
        _context: &Context,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        request.satisfy::<ScramStoredPassword>(&ScramStoredPassword {
            iterations: 4096,
            salt: self.salt,
            stored_key: self.stored_key.as_slice(),
            server_key: self.server_key.as_slice(),
        })?;
        request.satisfy::<Password>(b"password")?;

        Ok(())
    }

    fn validate(
        &self,
        _session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        let authid = context.get_ref::<AuthId>();

        validate.with::<SaslValidation, _>(|| match authid {
            Some(user) => Ok(Ok(String::from(user))),
            _ => Ok(Err(anyhow!("Unknown user"))),
        })?;

        Ok(())
    }
}
