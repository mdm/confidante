use std::{
    fmt::{Debug, Display},
    future::Future,
    str::FromStr,
};

use anyhow::{bail, Error};
use base64::prelude::*;
use tokio::io::ReadHalf;
use tokio_stream::StreamExt;

use crate::{
    services::store::StoreHandle,
    xml::{
        namespaces,
        stream_parser::{Frame, StreamParser},
        Element,
    },
    xmpp::{
        jid::Jid,
        stream::{Connection, XmppStream},
    },
};

pub use self::plain::StoredPasswordArgon2;
pub use self::scram::StoredPasswordScram;

mod plain;
mod scram;

#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct AuthenticatedEntity(pub String, ());

pub struct SaslNegotiator {
    _private: (),
}

impl SaslNegotiator {
    pub fn advertise_feature(secure: bool, authenticated: bool) -> Element {
        let mut mechanisms = Element::new("mechanisms", Some(namespaces::XMPP_SASL));

        let mut no_mechanisms = true;
        if Self::mechanism_available(&Mechanism::External, secure, authenticated) {
            mechanisms.add_element(Mechanism::External.to_element());
            no_mechanisms = false;
        }
        if Self::mechanism_available(&Mechanism::ScramSha1, secure, authenticated) {
            mechanisms.add_element(Mechanism::ScramSha1.to_element());
            no_mechanisms = false;
        }
        if Self::mechanism_available(&Mechanism::Plain, secure, authenticated) {
            mechanisms.add_element(Mechanism::Plain.to_element());
            no_mechanisms = false;
        }

        if no_mechanisms {
            todo!("make sure at least one mechanism is available");
        }

        mechanisms.set_attribute("xmlns", None, namespaces::XMPP_SASL.to_string());

        mechanisms
    }

    pub async fn negotiate_feature<C, P>(
        stream: &mut XmppStream<C, P>,
        element: &Element,
        store: StoreHandle,
    ) -> Result<Jid, Error>
    where
        C: Connection,
        P: StreamParser<ReadHalf<C>>,
    {
        if element.validate("auth", Some(namespaces::XMPP_SASL)) {
            bail!("expected auth element");
        }

        let mechanism = match element.attribute("mechanism", None) {
            Some(mechanism) => Mechanism::try_from(mechanism).unwrap(),
            None => bail!("auth element is missing mechanism attribute"),
        };

        let mut negotiator = mechanism.negotiator(store)?;
        let mut response_payload = BASE64_STANDARD.decode(element.text()).unwrap();

        loop {
            let result = negotiator.process(response_payload).await;

            match result {
                MechanismNegotiatorResult::Challenge(challenge) => {
                    let challenge = BASE64_STANDARD.encode(challenge);
                    let mut xml = Element::new("challenge", Some(namespaces::XMPP_SASL));
                    xml.set_attribute("xmlns", None, namespaces::XMPP_SASL.to_string());
                    xml.add_text(challenge);

                    stream.writer().write_xml_element(&xml).await?;
                }
                MechanismNegotiatorResult::Success(jid, additional_data) => {
                    let mut xml = Element::new("success", Some(namespaces::XMPP_SASL));
                    xml.set_attribute("xmlns", None, namespaces::XMPP_SASL.to_string());
                    if let Some(additional_data) = additional_data {
                        xml.add_text(BASE64_STANDARD.encode(additional_data));
                    }

                    stream.writer().write_xml_element(&xml).await?;
                    return Ok(jid);
                }
                MechanismNegotiatorResult::Failure(_err) => {
                    let mut xml = Element::new("failure", Some(namespaces::XMPP_SASL));
                    xml.set_attribute("xmlns", None, namespaces::XMPP_SASL.to_string());
                    xml.add_element(Element::new("not-authorized", Some(namespaces::XMPP_SASL)));

                    stream.writer().write_xml_element(&xml).await?;
                }
            }

            let Some(Ok(Frame::XmlFragment(response))) = stream.reader().next().await else {
                bail!("expected xml fragment");
            };

            if response.validate("response", Some(namespaces::XMPP_SASL)) {
                response_payload = BASE64_STANDARD.decode(response.text()).unwrap();
            } else if response.validate("abort", Some(namespaces::XMPP_SASL)) {
                bail!("authentication aborted");
            } else {
                bail!("unexpected element");
            }
        }
    }

    fn mechanism_available(mechanism: &Mechanism, secure: bool, authenticated: bool) -> bool {
        match mechanism {
            Mechanism::External => secure && authenticated,
            Mechanism::Plain => secure,
            Mechanism::ScramSha1 => true,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SaslError {
    #[error("the SASL mechanism `{0}` is not supported")]
    UnsupportedMechanism(String),
}

enum Mechanism {
    External,
    Plain,
    ScramSha1,
}

impl Mechanism {
    fn to_element(&self) -> Element {
        let mut element = Element::new("mechanism", Some(namespaces::XMPP_SASL));
        element.add_text(self.to_string());

        element
    }

    fn negotiator(&self, store: StoreHandle) -> Result<impl MechanismNegotiator, Error> {
        match self {
            Mechanism::External => todo!(),
            Mechanism::Plain => todo!(),
            Mechanism::ScramSha1 => scram::ScramSha1Negotiator::new("localhost".to_string(), store),
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
        }
    }
}

pub trait StoredPassword: FromStr + Display {
    fn new(plaintext: &str) -> Result<Self, Error>;
}

#[derive(Debug)]
pub enum StoredPasswordKind {
    Argon2,
    ScramSha1,
    ScramSha256,
}

enum MechanismNegotiatorResult {
    Challenge(Vec<u8>),
    Success(Jid, Option<Vec<u8>>),
    Failure(Error),
}

trait MechanismNegotiator {
    fn new(resolved_domain: String, store: StoreHandle) -> Result<Self, Error>
    where
        Self: Sized;
    fn process(
        &mut self,
        payload: Vec<u8>,
    ) -> impl Future<Output = MechanismNegotiatorResult> + Send;
}
