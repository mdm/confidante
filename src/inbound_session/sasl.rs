use std::ffi::CString;

use anyhow::{anyhow, bail, Error};
use bytes::{BufMut, BytesMut};
use rsasl::{session::Step, Callback, Property, ReturnCode, Session as SaslSession, SASL};

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

struct GsaslCallback;

impl Callback<(), ()> for GsaslCallback {
    fn callback(
        sasl: &mut SASL<(), ()>,
        session: &mut SaslSession<()>,
        prop: Property,
    ) -> Result<(), ReturnCode> {
        dbg!(&prop);

        match prop {
            Property::GSASL_PASSWORD => {
                let authcid = session
                    .get_property(Property::GSASL_AUTHID)
                    .ok_or(ReturnCode::GSASL_NO_AUTHID)?;

                session.set_property(
                    Property::GSASL_PASSWORD,
                    CString::new("password").unwrap().as_bytes(),
                );

                if authcid == CString::new("user").unwrap().as_ref() {
                    Ok(())
                } else {
                    Err(ReturnCode::GSASL_AUTHENTICATION_ERROR)
                }
            }
            _ => Err(ReturnCode::GSASL_NO_CALLBACK),
        }
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

        let mut sasl = SASL::new().map_err(|err| anyhow!(err))?;
        sasl.install_callback::<GsaslCallback>();


        let mut sasl_session = match mechanism {
            Mechanism::ScramSha1 => sasl
                .server_start("SCRAM-SHA-1")
                .map_err(|err| anyhow!(err))?,
            _ => todo!(),
        };

        let mut client_response = CString::new(fragment.content_str())?;
        let mut server_challenge_or_success = BytesMut::new();
        
        loop {
            {
                let step_result = sasl_session.step64(&client_response).map_err(|err| anyhow!(err))?;

                match step_result {
                    Step::NeedsMore(data) => {
                        let mut challenge = BytesMut::new();
                        challenge.put("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes());
                        challenge.put(data.to_bytes());
                        challenge.put("</challenge>".as_bytes());
                        dbg!("challenge sent");
                        server_challenge_or_success = challenge;
                    }
                    Step::Done(data) => {
                        // TODO: Compare identity to stream header
        
                        let mut success = BytesMut::new();
                        success.put("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes());
                        success.put(data.to_bytes());
                        success.put("</success>".as_bytes());
                        dbg!("success sent");
                        server_challenge_or_success = success;
                        break;
                    }
                }
            }
            session.write_buffer(&mut server_challenge_or_success).await?;

            let fragment = match session.read_frame().await? {
                Some(XmlFrame::XmlFragment(fragment)) => fragment,
                _ => bail!("expected xml fragment"),
            };
            if fragment.name != "response" {
                bail!("expected response tag");
            }

            client_response = CString::new(fragment.content_str())?;
        }

        dbg!("after loop");

        match sasl_session.get_property(Property::GSASL_AUTHID) {
            Some(entity) => Ok(AuthenticatedEntity(entity.to_owned().into_string()?, ())),
            None => todo!(),
        }
    }

    fn mechanism_available(&self, mechanism: Mechanism, session: &mut Session) -> bool {
        if session.connection.is_client_connection() {
            return match mechanism {
                Mechanism::External => match session.connection.security() {
                    Security::AuthenticatedTls => true,
                    _ => false,
                },
                Mechanism::ScramSha1Plus => match session.connection.security() {
                    Security::AuthenticatedTls => true,
                    Security::BasicTls => true,
                    _ => false,
                },
                _ => match session.connection.security() {
                    Security::None => !session.settings.tls.required_for_clients,
                    _ => true,
                },
            };
        }

        todo!()
    }
}
