use std::io::Cursor;

use anyhow::{anyhow, bail, Error};
use bytes::{BufMut, BytesMut};
use digest::{Digest, Output, generic_array::GenericArray};
use rsasl::{
    callback::{Context, Request, SessionCallback, SessionData},
    config::SASLConfig,
    mechanisms::scram,
    mechanisms::scram::properties::ScramStoredPassword,
    prelude::{SASLServer, SessionError, State},
    property::{AuthId, Password},
    validate::{Validate, Validation, ValidationError}, mechname::Mechname,
};
use sha1::Sha1;

use crate::xml_stream_parser::XmlFrame;

use super::session::Session;

#[derive(Debug)]
pub struct AuthenticatedEntity(pub String, ());

enum Mechanism {
    External,
    Plain,
    ScramSha1,
    ScramSha1Plus,
}

impl TryFrom<&str> for Mechanism {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "EXTERNAL" => Ok(Mechanism::External),
            "PLAIN" => Ok(Mechanism::Plain),
            "SCRAM-SHA-1" => Ok(Mechanism::ScramSha1),
            "SCRAM-SHA-1-PLUS" => Ok(Mechanism::ScramSha1Plus),
            _ => bail!(SaslError::UnsupportedMechanism(value.into())),
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
        let authid = context
            .get_ref::<AuthId>();

        validate.with::<SaslValidation, _>(|| {
            match authid {
                Some(user @ "user") => Ok(Ok(String::from(user))),
                _ => Ok(Err(anyhow!("Unknown user"))),
            }
        })?;
        

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SaslError {
    #[error("the SASL mechanism `{0}` is not supported")]
    UnsupportedMechanism(String),
}

pub struct SaslNegotiator {
    _private: (),
}

impl SaslNegotiator {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub async fn advertise_feature(&self, session: &mut Session) -> Result<(), Error> {
        let mut any_mechanism_available = false;
        let mut buffer = BytesMut::new();

        if self.mechanism_available(Mechanism::External, session) {
            buffer.put("    <mechanism>EXTERNAL</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }
        if self.mechanism_available(Mechanism::ScramSha1Plus, session) {
            buffer.put("    <mechanism>SCRAM-SHA-1-PLUS</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }
        if self.mechanism_available(Mechanism::ScramSha1, session) {
            buffer.put("    <mechanism>SCRAM-SHA-1</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }
        if self.mechanism_available(Mechanism::Plain, session) {
            buffer.put("    <mechanism>PLAIN</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }

        if any_mechanism_available {
            session
                .write_bytes("<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">\n".as_bytes())
                .await?;
            session.write_buffer(&mut buffer).await?;
            session.write_bytes("</mechanisms>\n".as_bytes()).await?;
        }

        Ok(())
    }

    pub async fn authenticate(&self, session: &mut Session) -> Result<AuthenticatedEntity, Error> {
        let fragment = match session.read_frame().await? {
            Some(XmlFrame::XmlFragment(fragment)) => fragment,
            _ => bail!("expected xml fragment"),
        };
        if fragment.name != "auth" {
            bail!("expected auth tag");
        }

        let mechanism = match fragment.get_attribute("mechanism", None) {
            Some(mechanism) => Mechanism::try_from(mechanism)?,
            None => bail!("auth element is missing mechanism attribute"),
        };

        // TODO: verify mechanism is available

        let plain_password = b"password";
        let salt = b"bad salt";
        let mut salted_password = GenericArray::default();
        // Derive the PBKDF2 key from the password and salt. This is the expensive part
        // TODO: do we need to off-load this to a separate thread? bechnmark!
        scram::tools::hash_password::<Sha1>(plain_password, 4096, &salt[..], &mut salted_password);
        let (client_key, server_key) = scram::tools::derive_keys::<Sha1>(salted_password.as_slice());
        let stored_key = Sha1::digest(&client_key);

        let sasl_config = SASLConfig::builder()
            .with_defaults()
            .with_callback(SaslCallback { salt, server_key, stored_key })?;

        let sasl = SASLServer::<SaslValidation>::new(sasl_config);

        let mut sasl_session = match mechanism {
            Mechanism::ScramSha1 => sasl
                .start_suggested(Mechname::parse(b"SCRAM-SHA-1").unwrap())?,
            _ => todo!(),
        };

        let mut client_response = base64::decode(fragment.content_str())?;
        let mut server_challenge_or_success = BytesMut::new();

        let mut do_last_step = false;
        let mut done = false;
        loop {
            {
                let mut out = Cursor::new(Vec::new());
                let step_result = if do_last_step {
                    do_last_step = false;
                    sasl_session
                    .step(None, &mut out)?
                } else { 
                    sasl_session
                    .step(Some(&client_response), &mut out)?
                };

                match step_result {
                    (State::Running, Some(len)) => {
                        let mut challenge = BytesMut::new();
                        challenge
                            .put("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes());
                        let encoded = base64::encode(&out.into_inner()[..len]);
                        challenge.put(encoded.as_bytes());
                        challenge.put("</challenge>".as_bytes());
                        server_challenge_or_success = challenge;
                    }
                    (State::Running, None) => {
                        do_last_step = true;
                    }
                    (State::Finished, Some(len)) => {
                        // TODO: Compare identity to stream header

                        let mut success = BytesMut::new();
                        success
                            .put("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes());
                        let encoded = base64::encode(&out.into_inner()[..len]);
                        success.put(encoded.as_bytes());
                        success.put("</success>".as_bytes());
                        server_challenge_or_success = success;
                        done = true;
                    }
                    (State::Finished, None) => {
                        // TODO: Compare identity to stream header

                        let mut success = BytesMut::new();
                        success
                            .put("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl' />".as_bytes());
                        server_challenge_or_success = success;
                        done = true;
                    }
                }
            }

            // dbg!(&server_challenge_or_success);

            session
                .write_buffer(&mut server_challenge_or_success)
                .await?;

            if done {
                break;
            }

            let fragment = match session.read_frame().await? {
                Some(XmlFrame::XmlFragment(fragment)) => fragment,
                _ => bail!("expected xml fragment"),
            };
            if fragment.name != "response" {
                bail!("expected response tag");
            }

            client_response = base64::decode(fragment.content_str())?;
        }

        match sasl_session.validation() {
            Some(Ok(entity)) => Ok(AuthenticatedEntity(entity, ())),
            _ => Err(anyhow!("validation failed")),
        }
    }

    fn mechanism_available(&self, mechanism: Mechanism, session: &mut Session) -> bool {
        // if session.connection.is_client_connection() {
        //     return match mechanism {
        //         Mechanism::External => match session.connection.security() {
        //             Security::AuthenticatedTls => true,
        //             _ => false,
        //         },
        //         Mechanism::ScramSha1Plus => match session.connection.security() {
        //             Security::AuthenticatedTls => true,
        //             Security::BasicTls => true,
        //             _ => false,
        //         },
        //         _ => match session.connection.security() {
        //             Security::None => !session.settings.tls.required_for_clients,
        //             _ => true,
        //         },
        //     };
        // }

        true
    }
}
