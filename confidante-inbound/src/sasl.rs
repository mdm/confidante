use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use anyhow::{Error, anyhow};
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
        stream::{Connection, StreamError, XmppStream},
    },
};

use crate::{
    FeatureNegotiator, StreamFeature, StreamInfo,
    sasl::{plain::PlainNegotiator, scram::ScramNegotiator},
};

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

#[derive(Debug, thiserror::Error)]
enum SaslError {
    #[error("authentication aborted by client")]
    Aborted,
    #[error("account disabled by server administrator")]
    AccountDisabled,
    #[error("client credentials have expired")]
    CredentialsExpired,
    #[error("encryption required for requested authentication mechanism")]
    EncryptionRequired,
    #[error("authentication data has invalid encoding")]
    IncorrectEncoding,
    #[error("cannot authenticate as the specified authzid")]
    InvalidAuthzid,
    #[error("authentication mechanism is invalid")]
    InvalidMechanism,
    #[error("malformed authentication request")]
    MalformedRequest,
    #[error("authentication mechanism is too weak")]
    MechanismTooWeak,
    #[error("could not authenticate with the provided credentials")]
    NotAuthorized,
    #[error("temporary authentication failure")]
    TemporaryAuthFailure,
}

impl From<SaslError> for Element {
    fn from(value: SaslError) -> Self {
        let mut xml = Element::new("failure", Some(namespaces::XMPP_SASL));
        xml.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);

        let name = match value {
            SaslError::Aborted => "abort",
            SaslError::AccountDisabled => "account-disabled",
            SaslError::CredentialsExpired => "credentials-expired",
            SaslError::EncryptionRequired => "encryption-required",
            SaslError::IncorrectEncoding => "incorrect-encoding",
            SaslError::InvalidAuthzid => "invalid-authzid",
            SaslError::InvalidMechanism => "invalid-mechanism",
            SaslError::MalformedRequest => "malformed-request",
            SaslError::MechanismTooWeak => "mechanism-too-weak",
            SaslError::NotAuthorized => "not-authorized",
            SaslError::TemporaryAuthFailure => "temporary-auth-failure",
        };

        xml.add_child(Element::new(name, Some(namespaces::XMPP_SASL)));

        xml
    }
}

pub(super) struct SaslNegotiator<S> {
    store: S,
}

impl<S> SaslNegotiator<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    fn mechanism_available(
        &self,
        mechanism: &Mechanism,
        secure: bool,
        authenticated: bool,
    ) -> Result<(), SaslError> {
        if matches!(mechanism, Mechanism::Plain | Mechanism::ScramSha1) {
            return Ok(());
        } else {
            return Err(SaslError::InvalidMechanism);
        }

        // match mechanism {
        //     Mechanism::External => secure && authenticated,
        //     Mechanism::Plain => secure,
        //     Mechanism::ScramSha1 => true,
        //     Mechanism::ScramSha1Plus => true,
        //     Mechanism::ScramSha256 => true,
        //     Mechanism::ScramSha256Plus => true,
        // }
    }
}

#[async_trait::async_trait]
impl<C, P, S> FeatureNegotiator<C, P> for SaslNegotiator<S>
where
    C: Connection + Send,
    P: StreamParser<ReadHalf<C>> + Send,
    S: StoredPasswordLookup + Send + Sync,
{
    fn advertise_feature(&self, info: &StreamInfo) -> Element {
        let mut mechanisms = Element::new("mechanisms", Some(namespaces::XMPP_SASL));

        // TODO: make mechanisms available based on configured policy
        mechanisms.add_child(Mechanism::ScramSha1.into());
        mechanisms.add_child(Mechanism::Plain.into());

        mechanisms.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);

        mechanisms
    }

    async fn negotiate_feature(
        &self,
        element: &Element,
        stream: &mut XmppStream<C, P>,
        info: &mut StreamInfo,
    ) -> Result<bool, StreamError> {
        if !element.validate("auth", Some(namespaces::XMPP_SASL)) {
            return Ok(false);
        }

        let mechanism = match element.attribute("mechanism", None::<String>) {
            Some(mechanism) => match Mechanism::try_from(mechanism) {
                Ok(mechanism) => mechanism,
                Err(_) => {
                    stream
                        .writer()
                        .write_xml_element(&SaslError::InvalidMechanism.into())
                        .await?;

                    return Ok(false);
                }
            },
            None => {
                stream
                    .writer()
                    .write_xml_element(&SaslError::InvalidMechanism.into())
                    .await?;

                return Ok(false);
            }
        };

        if let Err(error) =
            self.mechanism_available(&mechanism, stream.is_secure(), stream.is_authenticated())
        {
            stream.writer().write_xml_element(&error.into()).await?;

            return Ok(false);
        }

        let mut negotiator = mechanism.negotiator(self.store.clone())?;
        let Ok(mut response_payload) = BASE64_STANDARD.decode(element.text()) else {
            stream
                .writer()
                .write_xml_element(&SaslError::IncorrectEncoding.into())
                .await?;

            return Ok(false);
        };

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
                MechanismNegotiatorResult::Success(additional_data) => {
                    let authzid = match negotiator.authorization_id().await {
                        Ok(authzid) => authzid,
                        Err(_) => {
                            // TODO: distinguish between different error cases and send appropriate failure responses
                            stream
                                .writer()
                                .write_xml_element(&SaslError::NotAuthorized.into())
                                .await?;

                            return Ok(false);
                        }
                    };

                    let Some(peer_jid) = info.peer_jid.take() else {
                        // This should never happen. Peer JID should have been set during virtual host resolution.
                        return Err(anyhow!("JID was not set before authentication").into());
                    };

                    info.peer_jid = Some(peer_jid.with_local(Some(authzid)));
                    info.features.insert(StreamFeature::Authentication);

                    let mut xml = Element::new("success", Some(namespaces::XMPP_SASL));
                    xml.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);
                    if let Some(additional_data) = additional_data {
                        xml.add_text(BASE64_STANDARD.encode(additional_data));
                    }

                    stream.writer().write_xml_element(&xml).await?;

                    return Ok(true);
                }
                MechanismNegotiatorResult::Failure(_err) => {
                    let mut xml = Element::new("failure", Some(namespaces::XMPP_SASL));
                    xml.set_attribute("xmlns", None::<String>, namespaces::XMPP_SASL);
                    xml.add_child(Element::new("not-authorized", Some(namespaces::XMPP_SASL)));

                    stream.writer().write_xml_element(&xml).await?;
                }
            }

            let Some(Ok(Frame::XmlFragment(response))) = stream.reader().next().await else {
                // TODO: handle end of stream and stream errors
                return Err(anyhow!("expected xml fragment").into());
            };

            if response.validate("response", Some(namespaces::XMPP_SASL)) {
                response_payload = match BASE64_STANDARD.decode(response.text()) {
                    Ok(payload) => payload,
                    Err(_) => {
                        stream
                            .writer()
                            .write_xml_element(&SaslError::IncorrectEncoding.into())
                            .await?;

                        return Ok(false);
                    }
                };
            } else {
                if response.validate("abort", Some(namespaces::XMPP_SASL)) {
                    stream
                        .writer()
                        .write_xml_element(&SaslError::Aborted.into())
                        .await?;
                }

                return Ok(false);
            }
        }
    }

    fn requires_restart(&self) -> bool {
        true
    }
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
            Mechanism::Plain => {
                PlainNegotiator::new("localhost".to_string(), store).map(MechanismNegotiator::Plain)
            }
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
    type Error = SaslError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "EXTERNAL" => Ok(Mechanism::External),
            "PLAIN" => Ok(Mechanism::Plain),
            "SCRAM-SHA-1" => Ok(Mechanism::ScramSha1),
            _ => Err(SaslError::InvalidMechanism),
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

enum MechanismPolicy {
    Enabled,
    EncryptionRequired,
    TooWeak,
    Disabled,
}

enum MechanismNegotiatorResult {
    Challenge(Vec<u8>),
    Success(Option<Vec<u8>>),
    Failure(Error),
}

enum MechanismNegotiator<S> {
    External,
    Plain(PlainNegotiator<S>),
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
            MechanismNegotiator::Plain(negotiator) => negotiator.process(payload).await,
            MechanismNegotiator::ScramSha1(negotiator) => negotiator.process(payload).await,
            MechanismNegotiator::ScramSha1Plus(negotiator) => negotiator.process(payload).await,
            MechanismNegotiator::ScramSha256(negotiator) => negotiator.process(payload).await,
            MechanismNegotiator::ScramSha256Plus(negotiator) => negotiator.process(payload).await,
        }
    }

    async fn authorization_id(self) -> Result<String, Error> {
        match self {
            MechanismNegotiator::External => todo!(),
            MechanismNegotiator::Plain(negotiator) => negotiator.authorization_id().await,
            MechanismNegotiator::ScramSha1(negotiator) => negotiator.authorization_id().await,
            MechanismNegotiator::ScramSha1Plus(negotiator) => negotiator.authorization_id().await,
            MechanismNegotiator::ScramSha256(negotiator) => negotiator.authorization_id().await,
            MechanismNegotiator::ScramSha256Plus(negotiator) => negotiator.authorization_id().await,
        }
    }
}
