use anyhow::{bail, Error};
use bytes::{BytesMut, BufMut};
use sasl::{
    impl_validator_using_provider,
    common::{Identity, Password, scram::{ScramProvider, Sha1}},
    server::{mechanisms, Mechanism as ServerMechanism, Response, Provider, ProviderError, ValidatorError},
    secret,
};

use crate::xml_stream_parser::XmlFrame;

use super::connection::Security;
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

struct SaslValidator;

impl Provider<secret::Pbkdf2Sha1> for SaslValidator {
    fn provide(&self, _identity: &Identity) -> Result<secret::Pbkdf2Sha1, ProviderError> {
        // TODO: implement proper identity-based authentiation

        const SALT: [u8; 8] = [35, 71, 92, 105, 212, 219, 114, 93];
        const ITERATIONS: u32 = 4096;

        let digest = sasl::common::scram::Sha1::derive
            ( &Password::Plain("password".to_owned())
            , &SALT[..]
            , ITERATIONS )?;
        Ok(secret::Pbkdf2Sha1 {
            salt: SALT.to_vec(),
            iterations: ITERATIONS,
            digest: digest,
        })
    }
}

impl_validator_using_provider!(SaslValidator, secret::Pbkdf2Sha1);

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
        Self {
            _private: (),
        }
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
            session.write_bytes("<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">\n".as_bytes()).await?;
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

        let mut mechanism = match mechanism {
            Mechanism::ScramSha1 => mechanisms::Scram::<Sha1, _>::new(SaslValidator, sasl::common::ChannelBinding::Unsupported),
            _ => todo!(),
        };

        let mut initial = base64::decode(fragment.content_str())?;
        initial[0] = 0x79; // TODO: hack to work around channel binding bug in sasl crate   
        dbg!(String::from_utf8(initial.clone()));

        let mut response = mechanism.respond(initial.as_slice())?;

        loop {
            match response {
                Response::Proceed(ref data) => {
                    dbg!(String::from_utf8(data.clone()));
                    let challenge = base64::encode(data);
                    session.write_bytes("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes()).await?;
                    session.write_bytes(challenge.as_bytes()).await?;
                    session.write_bytes("</challenge>".as_bytes()).await?;
                    dbg!("challenge sent");
                },
                _ => break,
            }

            let fragment = match session.read_frame().await? {
                Some(XmlFrame::XmlFragment(fragment)) => fragment,
                _ => bail!("expected xml fragment"),
            };
            if fragment.name != "response" {
                bail!("expected response tag");
            }

            let msg = base64::decode(fragment.content_str())?;
            dbg!(String::from_utf8(msg.clone()));
    
            response = mechanism.respond(msg.as_slice())?;
        }

        dbg!("after loop");

        match response {
            Response::Success(identity, data) => {
                // TODO: Compare identity to stream header

                let success = base64::encode(data);
                dbg!(&success);
                session.write_bytes("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes()).await?;
                session.write_bytes(success.as_bytes()).await?;
                session.write_bytes("</success>".as_bytes()).await?;

                match identity {
                    Identity::Username(entity) => Ok(AuthenticatedEntity(entity, ())),
                    Identity::None => todo!(),
                }
            }
            _ => todo!(),
        }
    }

    fn mechanism_available(&self, mechanism: Mechanism, session: &mut Session) -> bool {
        if session.connection.is_client_connection() {
            return match mechanism {
                Mechanism::External => match session.connection.security() {
                    Security::AuthenticatedTls => true,
                    _ => false,
                }
                Mechanism::ScramSha1Plus => match session.connection.security() {
                    Security::AuthenticatedTls => true,
                    Security::BasicTls => true,
                    _ => false,
                }
                _ => match session.connection.security() {
                    Security::None => !session.settings.tls.required_for_clients,
                    _ => true,
                }
            }
        }

        todo!()
    }
}
