use std::{collections::HashMap, fmt::Display};

use anyhow::{bail, Error};
use base64::prelude::*;
use tokio_stream::StreamExt;

use crate::{
    xml::{namespaces, stream_parser::Frame, Element, Node},
    xmpp::{
        jid::Jid,
        stream::{Connection, XmppStream},
    },
};

mod scram;

#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct AuthenticatedEntity(pub String, ());

pub struct SaslNegotiator {
    _private: (),
}

impl SaslNegotiator {
    pub fn advertise_feature(secure: bool, authenticated: bool) -> Element {
        let mut available_mechanisms = Vec::new();

        if Self::mechanism_available(&Mechanism::External, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::External.to_element()));
        }
        if Self::mechanism_available(&Mechanism::ScramSha1Plus, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::ScramSha1Plus.to_element()));
        }
        if Self::mechanism_available(&Mechanism::ScramSha1, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::ScramSha1.to_element()));
        }
        if Self::mechanism_available(&Mechanism::Plain, secure, authenticated) {
            available_mechanisms.push(Node::Element(Mechanism::Plain.to_element()));
        }

        if available_mechanisms.is_empty() {
            todo!("make sure at least one mechanism is available");
        }

        let mut attributes = HashMap::new();
        attributes.insert(
            ("xmlns".to_string(), None),
            namespaces::XMPP_SASL.to_string(),
        );

        Element {
            name: "mechanisms".to_string(),
            namespace: Some(namespaces::XMPP_SASL.to_string()),
            attributes,
            children: available_mechanisms,
        }
    }

    pub async fn negotiate_feature<C>(
        stream: &mut XmppStream<C>,
        element: &Element,
    ) -> Result<Jid, Error>
    where
        C: Connection,
    {
        if element.name != "auth" || element.namespace != Some(namespaces::XMPP_SASL.to_string()) {
            bail!("expected auth element");
        }

        let mechanism = match element.get_attribute("mechanism", None) {
            Some(mechanism) => Mechanism::try_from(mechanism).unwrap(), // TODO: handle "invalid-mechanism"
            None => bail!("auth element is missing mechanism attribute"),
        };

        // TODO: verify mechanism is available

        let mut negotiator = mechanism.negotiator()?; // TODO: handle error locally
        let mut response_payload = BASE64_STANDARD.decode(element.get_text()).unwrap(); // TODO: handle "incorrect-encoding"

        loop {
            let result = negotiator.process(response_payload);

            match result {
                MechanismNegotiatorResult::Challenge(challenge) => {
                    let challenge = BASE64_STANDARD.encode(challenge);
                    let xml = Element {
                        name: "challenge".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: vec![(
                            ("xmlns".to_string(), None),
                            namespaces::XMPP_SASL.to_string(),
                        )]
                        .into_iter()
                        .collect(),
                        children: vec![Node::Text(challenge)],
                    };
                    stream.writer().write_xml_element(&xml).await?;
                }
                MechanismNegotiatorResult::Success(jid, additional_data) => {
                    let children = match additional_data {
                        Some(additional_data) => {
                            vec![Node::Text(BASE64_STANDARD.encode(additional_data))]
                        }
                        None => vec![],
                    };
                    let xml = Element {
                        name: "success".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: vec![(
                            ("xmlns".to_string(), None),
                            namespaces::XMPP_SASL.to_string(),
                        )]
                        .into_iter()
                        .collect(),
                        children,
                    };
                    stream.writer().write_xml_element(&xml).await?;
                    return Ok(jid);
                }
                MechanismNegotiatorResult::Failure(_err) => {
                    let reason = Element {
                        name: "not-authorized".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: HashMap::new(),
                        children: vec![],
                    };
                    let xml = Element {
                        name: "failure".to_string(),
                        namespace: Some(namespaces::XMPP_SASL.to_string()),
                        attributes: vec![(
                            ("xmlns".to_string(), None),
                            namespaces::XMPP_SASL.to_string(),
                        )]
                        .into_iter()
                        .collect(),
                        children: vec![Node::Element(reason)],
                    };
                    stream.writer().write_xml_element(&xml).await?;
                }
            }

            let Some(Ok(Frame::XmlFragment(response))) = stream.reader().next().await else {
                bail!("expected xml fragment");
            };

            match response.name.as_str() {
                "response" => {
                    response_payload = BASE64_STANDARD.decode(response.get_text()).unwrap();
                    // TODO: handle "incorrect-encoding"
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

    fn mechanism_available(mechanism: &Mechanism, secure: bool, authenticated: bool) -> bool {
        match mechanism {
            Mechanism::External => secure && authenticated,
            Mechanism::Plain => secure,
            Mechanism::ScramSha1 => true,
            Mechanism::ScramSha1Plus => secure,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SaslError {
    // TODO: do we need this?
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

    fn negotiator(&self) -> Result<impl MechanismNegotiator, Error> {
        match self {
            Mechanism::External => todo!(),
            Mechanism::Plain => todo!(),
            Mechanism::ScramSha1 => scram::ScramSha1Negotiator::with_credentials(),
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

enum MechanismNegotiatorResult {
    Challenge(Vec<u8>),
    Success(Jid, Option<Vec<u8>>),
    Failure(Error),
}

trait MechanismNegotiator {
    fn with_credentials() -> Result<Self, Error>
    where
        Self: Sized;
    fn process(&mut self, payload: Vec<u8>) -> MechanismNegotiatorResult;
}
