use bytes::{BytesMut, BufMut};
use tokio::io::AsyncWriteExt;

use crate::settings::Settings;
use super::connection::{Connection, Security};
use super::Error;

enum Mechanism {
    External,
    Plain,
    ScramSha1,
    ScramSha1Plus,    
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
