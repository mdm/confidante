use anyhow::{bail, Error};
use bytes::{BytesMut, BufMut};
use rustyxml::Element;
use sasl::client::mechanisms;
use tokio::io::AsyncWriteExt;

use crate::settings::Settings;
use super::connection::{Connection, Security};

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


#[derive(thiserror::Error, Debug)]
pub enum SaslError {
    #[error("the SASL mechanism `{0}` is not supported")]
    UnsupportedMechanism(String),
}

pub struct SaslNegotiator {
    mechanism: Option<Mechanism>,
}

impl SaslNegotiator {
    pub fn new() -> Self {
        Self {
            mechanism: None
        }
    }

    pub async fn advertise_feature(&self, connection: &mut Connection, settings: &Settings) -> Result<(), Error> {
        let mut any_mechanism_available = false;
        let mut buffer = BytesMut::new();
        
        if self.mechanism_available(Mechanism::External, connection, settings) {
            buffer.put("    <mechanism>EXTERNAL</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }
        if self.mechanism_available(Mechanism::ScramSha1Plus, connection, settings) {
            buffer.put("    <mechanism>SCRAM-SHA-1-PLUS</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }
        if self.mechanism_available(Mechanism::ScramSha1, connection, settings) {
            buffer.put("    <mechanism>SCRAM-SHA-1</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }
        if self.mechanism_available(Mechanism::Plain, connection, settings) {
            buffer.put("    <mechanism>PLAIN</mechanism>\n".as_bytes());
            any_mechanism_available = true;
        }

        if any_mechanism_available {
            connection.socket().write_all("<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">\n".as_bytes()).await?;
            connection.socket().write_all_buf(&mut buffer).await?;
            connection.socket().write_all("</mechanisms>\n".as_bytes()).await?;
        }

        Ok(())
    }

    pub async fn respond(&mut self, connection: &mut Connection, settings: &Settings, fragment: Element) -> Result<bool, Error> {
        if fragment.name == "auth" {
            let mechanism = fragment.get_attribute("mechanism", None);
            let mechanism = match mechanism {
                Some(mechanism) => Mechanism::try_from(mechanism)?,
                None => bail!("auth element is missing mechanism attribute"),
            };
            self.mechanism = Some(mechanism);
        }

        Ok(true)
    }

    fn mechanism_available(&self, mechanism: Mechanism, connection: &mut Connection, settings: &Settings) -> bool {
        if connection.is_client_connection() {
            return match mechanism {
                Mechanism::External => match connection.security() {
                    Security::AuthenticatedTls => true,
                    _ => false,
                }
                Mechanism::ScramSha1Plus => match connection.security() {
                    Security::AuthenticatedTls => true,
                    Security::BasicTls => true,
                    _ => false,
                }
                _ => match connection.security() {
                    Security::None => !settings.tls.required_for_clients,
                    _ => true,
                }
            }
        }

        unimplemented!()
    }
}
