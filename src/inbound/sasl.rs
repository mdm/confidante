use std::{collections::HashMap, fmt::Display};

use anyhow::{anyhow, bail, Error};
use base64::prelude::*;
use tokio::io::AsyncWrite;
use tokio_stream::StreamExt;

use crate::xml::{namespaces, stream_parser::{Frame, StreamParser}, stream_writer::StreamWriter, Element, Node};

mod scram;

#[derive(Debug)]
pub struct AuthenticatedEntity(pub String, ());


pub struct SaslNegotiator {
    _private: (),
}

impl SaslNegotiator {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn advertise_feature(&self, secure: bool, authenticated: bool) -> Element {
        let mut available_mechanisms = Vec::new();

        if self.mechanism_available(&Mechanism::External, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::External.to_element()));
        }
        if self.mechanism_available(&Mechanism::ScramSha1Plus, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::ScramSha1Plus.to_element()));
        }
        if self.mechanism_available(&Mechanism::ScramSha1, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::ScramSha1.to_element()));
        }
        if self.mechanism_available(&Mechanism::Plain, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::Plain.to_element()));
        }

        if available_mechanisms.is_empty() {
            todo!("make sure at least one mechanism is available");
        }

        Element {
            name: "mechanisms".to_string(),
            namespace: Some(namespaces::XMPP_SASL.to_string()),
            attributes: HashMap::new(),
            children: available_mechanisms,
        }
    }

    pub async fn authenticate<P: StreamParser, W: AsyncWrite + Unpin>(
        &self,
        stream_parser: &mut P,
        stream_writer: &mut StreamWriter<W>,
        secure: bool,
        authenticated: bool,
    ) -> Result<AuthenticatedEntity, Error> {
        let Some(Ok(Frame::XmlFragment(auth))) = stream_parser.next().await else {
            bail!("expected xml fragment");
        };
        if auth.name != "auth" { // TODO: check namespace
            bail!("expected auth tag");
        }

        let mechanism = match auth.get_attribute("mechanism", None) {
            Some(mechanism) => Mechanism::try_from(mechanism)?,
            None => bail!("auth element is missing mechanism attribute"),
        };

        // TODO: verify mechanism is available

        let mut response_payload = BASE64_STANDARD.decode(auth.get_text()).unwrap(); // TODO: handle "incorrect-encoding"

        loop {
            let result = mechanism.negotiator().process(response_payload);    

            match result {
                Ok(Some(challenge)) => {
                    let challenge = BASE64_STANDARD.encode(challenge);
                    let xml = Element {
                        name: "challenge".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: HashMap::new(),
                        children: vec![Node::Text(challenge)],
                    };
                    stream_writer.write_xml_element(&xml).await?;
                }
                Ok(None) => {
                    let xml = Element {
                        name: "success".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: HashMap::new(),
                        children: vec![],
                    };
                    stream_writer.write_xml_element(&xml).await?;
                    return Ok(AuthenticatedEntity("user".to_string(), ())); // TODO: don't hard-code username
                }
                Err(err) => {
                    let reason = Element {
                        name: "not-authorized".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: HashMap::new(),
                        children: vec![],
                    };
                    let xml = Element {
                        name: "failure".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: HashMap::new(),
                        children: vec![Node::Element(reason)],
                    };
                    stream_writer.write_xml_element(&xml).await?;
                }                    
            }

            let Some(Ok(Frame::XmlFragment(response))) = stream_parser.next().await else {
                bail!("expected xml fragment");
            };

            match response.name.as_str() {
                "response" => {
                    response_payload = BASE64_STANDARD.decode(response.get_text()).unwrap(); // TODO: handle "incorrect-encoding"
                }
                "abort" => {
                    // TODO: send "failure" element
                    bail!("authentication aborted");
                }
                _ => {
                    // TODO: send "failure" element
                    bail!("unexpected element");
                }
            }


        }
        
    }

    fn mechanism_available(
        &self,
        mechanism: &Mechanism,
        secure: bool,
        authenticated: bool,
    ) -> bool {
        match mechanism {
            Mechanism::External => secure && authenticated,
            Mechanism::Plain => secure,
            Mechanism::ScramSha1 => true,
            Mechanism::ScramSha1Plus => secure,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SaslError { // TODO: do we need this?
    #[error("the SASL mechanism `{0}` is not supported")]
    UnsupportedMechanism(String),
}

enum Mechanism {
    External,
    Plain,
    ScramSha1,
    ScramSha1Plus,
}

impl Mechanism {
    fn to_element(&self) -> Element {
        Element {
            name: "mechanism".to_string(),
            namespace: Some(namespaces::XMPP_SASL.to_string()),
            attributes: HashMap::new(),
            children: vec![Node::Text(self.to_string())],
        }
    }

    fn negotiator(&self) -> impl MechanismNegotiator {
        match self {
            Mechanism::External => todo!(),
            Mechanism::Plain => todo!(),
            Mechanism::ScramSha1 => scram::ScramSha1Negotiator::new(),
            Mechanism::ScramSha1Plus => todo!(),
        }
    }
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

impl Display for Mechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mechanism::External => write!(f, "EXTERNAL"),
            Mechanism::Plain => write!(f, "PLAIN"),
            Mechanism::ScramSha1 => write!(f, "SCRAM-SHA-1"),
            Mechanism::ScramSha1Plus => write!(f, "SCRAM-SHA-1-PLUS"),
        }
    }
}

trait MechanismNegotiator {
    fn new() -> Self;
    fn process(&self, payload: Vec<u8>) -> Result<Option<Vec<u8>>, Error>;
}
