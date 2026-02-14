use std::{
    fmt::{Debug, Display},
    future::Future,
    str::FromStr,
};

use anyhow::{Error, bail};
use base64::prelude::*;
use sha1::Sha1;
use sha2::Sha256;
use tokio::io::ReadHalf;
use tokio_stream::StreamExt;

use confidante_core::{
    xml::{
        Element, namespaces,
        stream_parser::{Frame, StreamParser},
    },
    xmpp::{
        jid::Jid,
        stream::{Connection, XmppStream},
    },
};

use crate::sasl::scram::ScramNegotiator;

pub use self::plain::StoredPasswordArgon2;
pub use self::scram::StoredPasswordScram;

mod common;
mod plain;
mod scram;

pub trait StoredPassword: FromStr + Display {
    fn new(plaintext: &str) -> Result<Self, Error>;
}

pub trait StoredPasswordLookup: Clone + Debug {
    // TODO: get rid of Clone bound
    fn get_stored_password_argon2(
        &self,
        jid: Jid,
    ) -> impl std::future::Future<Output = Result<String, Error>> + Send;
    fn get_stored_password_scram_sha1(
        &self,
        jid: Jid,
    ) -> impl std::future::Future<Output = Result<String, Error>> + Send;
    fn get_stored_password_scram_sha256(
        &self,
        jid: Jid,
    ) -> impl std::future::Future<Output = Result<String, Error>> + Send;
}

pub(super) struct SaslNegotiator {
    _private: (),
}

impl SaslNegotiator {
    pub fn advertise_feature(secure: bool, authenticated: bool) -> Element {
        let mut mechanisms = Element::new("mechanisms", Some(namespaces::XMPP_SASL));

        let mut no_mechanisms = true;
        if Self::mechanism_available(&Mechanism::External, secure, authenticated) {
            mechanisms.add_child(Mechanism::External.into());
            no_mechanisms = false;
        }
        if Self::mechanism_available(&Mechanism::ScramSha1, secure, authenticated) {
            mechanisms.add_child(Mechanism::ScramSha1.into());
            no_mechanisms = false;
        }
        if Self::mechanism_available(&Mechanism::Plain, secure, authenticated) {
            mechanisms.add_child(Mechanism::Plain.into());
            no_mechanisms = false;
        }

        if no_mechanisms {
            todo!("make sure at least one mechanism is available");
        }

        mechanisms.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);

        mechanisms
    }

    pub async fn negotiate_feature<C, P, S>(
        stream: &mut XmppStream<C, P>,
        element: &Element,
        store: S,
    ) -> Result<Jid, Error>
    where
        C: Connection,
        P: StreamParser<ReadHalf<C>>,
        S: StoredPasswordLookup + Send + Sync,
    {
        if !element.validate("auth", Some(namespaces::XMPP_SASL)) {
            bail!("expected auth element");
        }

        let mechanism = match element.attribute("mechanism", None::<String>) {
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
                    xml.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);
                    xml.add_text(challenge);

                    stream.writer().write_xml_element(&xml).await?;
                }
                MechanismNegotiatorResult::Success(jid, additional_data) => {
                    let mut xml = Element::new("success", Some(namespaces::XMPP_SASL));
                    xml.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);
                    if let Some(additional_data) = additional_data {
                        xml.add_text(BASE64_STANDARD.encode(additional_data));
                    }

                    stream.writer().write_xml_element(&xml).await?;
                    return Ok(jid);
                }
                MechanismNegotiatorResult::Failure(_err) => {
                    let mut xml = Element::new("failure", Some(namespaces::XMPP_SASL));
                    xml.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);
                    xml.add_child(Element::new("not-authorized", Some(namespaces::XMPP_SASL)));

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
            Mechanism::ScramSha1Plus => true,
            Mechanism::ScramSha256 => true,
            Mechanism::ScramSha256Plus => true,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub(super) enum SaslError {
    #[error("the SASL mechanism `{0}` is not supported")]
    UnsupportedMechanism(String),
}

#[derive(Debug, Clone, Copy)]
enum Mechanism {
    External,
    Plain,
    ScramSha1,
    ScramSha1Plus,
    ScramSha256,
    ScramSha256Plus,
}

impl Mechanism {
    fn negotiator<S>(&self, store: S) -> Result<MechanismNegotiator<S>, Error>
    where
        S: StoredPasswordLookup + Send + Sync,
    {
        match self {
            Mechanism::External => todo!(),
            Mechanism::Plain => todo!(),
            Mechanism::ScramSha1 => {
                ScramNegotiator::<S, Sha1>::new("localhost".to_string(), false, store)
                    .map(MechanismNegotiator::ScramSha1)
            }
            Mechanism::ScramSha1Plus => {
                ScramNegotiator::<S, Sha1>::new("localhost".to_string(), true, store)
                    .map(MechanismNegotiator::ScramSha1Plus)
            }
            Mechanism::ScramSha256 => {
                ScramNegotiator::<S, Sha256>::new("localhost".to_string(), false, store)
                    .map(MechanismNegotiator::ScramSha256)
            }
            Mechanism::ScramSha256Plus => {
                ScramNegotiator::<S, Sha256>::new("localhost".to_string(), true, store)
                    .map(MechanismNegotiator::ScramSha256Plus)
            }
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
            Mechanism::ScramSha1Plus => write!(f, "SCRAM-SHA-1-PLUS"),
            Mechanism::ScramSha256 => write!(f, "SCRAM-SHA-256"),
            Mechanism::ScramSha256Plus => write!(f, "SCRAM-SHA-256-PLUS"),
        }
    }
}

impl From<Mechanism> for Element {
    fn from(mechanism: Mechanism) -> Self {
        let mut element = Element::new("mechanism", Some(namespaces::XMPP_SASL));
        element.add_text(mechanism.to_string());

        element
    }
}

enum MechanismNegotiatorResult {
    Challenge(Vec<u8>),
    Success(Jid, Option<Vec<u8>>),
    Failure(Error),
}

enum MechanismNegotiator<S> {
    External,
    Plain,
    ScramSha1(ScramNegotiator<S, Sha1>),
    ScramSha1Plus(ScramNegotiator<S, Sha1>),
    ScramSha256(ScramNegotiator<S, Sha256>),
    ScramSha256Plus(ScramNegotiator<S, Sha256>),
}

impl<S> MechanismNegotiator<S>
where
    S: StoredPasswordLookup + Send + Sync,
{
    async fn process(&mut self, payload: Vec<u8>) -> MechanismNegotiatorResult {
        match self {
            MechanismNegotiator::External => todo!(),
            MechanismNegotiator::Plain => todo!(),
            MechanismNegotiator::ScramSha1(negotiator) => negotiator.process(payload).await,
            MechanismNegotiator::ScramSha1Plus(negotiator) => negotiator.process(payload).await,
            MechanismNegotiator::ScramSha256(negotiator) => negotiator.process(payload).await,
            MechanismNegotiator::ScramSha256Plus(negotiator) => negotiator.process(payload).await,
        }
    }

    async fn authentication_id(self) -> Result<String, Error> {
        match self {
            MechanismNegotiator::External => todo!(),
            MechanismNegotiator::Plain => todo!(),
            MechanismNegotiator::ScramSha1(negotiator) => negotiator.authentication_id().await,
            MechanismNegotiator::ScramSha1Plus(negotiator) => negotiator.authentication_id().await,
            MechanismNegotiator::ScramSha256(negotiator) => negotiator.authentication_id().await,
            MechanismNegotiator::ScramSha256Plus(negotiator) => {
                negotiator.authentication_id().await
            }
        }
    }
}
