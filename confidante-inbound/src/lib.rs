use std::collections::HashSet;

use anyhow::{Error, anyhow, bail};
use sasl::StoredPasswordLookup;
use tokio::io::ReadHalf;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::StreamExt;

use confidante_core::xml::namespaces;
use confidante_core::xml::stream_parser::StreamParser;
use confidante_core::xml::{Element, stream_parser::Frame};
use confidante_core::xmpp::jid::Jid;
use confidante_core::xmpp::stanza::Stanza;
use confidante_core::xmpp::stream::StreamError;
use confidante_core::xmpp::stream::StreamId;
use confidante_core::xmpp::stream::XmppStream;
use confidante_core::xmpp::stream::{Connection, ConnectionType};
use confidante_core::xmpp::stream_header::LanguageTag;
use confidante_core::xmpp::stream_header::StreamHeader;
use confidante_services::router::ManagementCommand;
use confidante_services::router::RouterHandle;

pub mod bind;
pub mod connection;
pub mod sasl;
pub mod starttls;

const STANZA_CHANNEL_BUFFER_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
enum StreamFeature {
    Tls,
    Authentication,
    ResourceBinding,
}

struct StreamInfo {
    stream_id: StreamId,
    jid: Option<Jid>,
    peer_jid: Option<Jid>,
    peer_language: Option<LanguageTag>,
    features: HashSet<StreamFeature>,
}

impl Default for StreamInfo {
    fn default() -> Self {
        StreamInfo {
            stream_id: StreamId::new(),
            jid: None,
            peer_jid: None,
            peer_language: None,
            features: HashSet::new(),
        }
    }
}

pub struct InboundStreamSettings {
    pub domain: Jid,
}

pub struct InboundStream<C, P, S>
where
    C: Connection + Send,
    P: StreamParser<ReadHalf<C>> + Send,
    S: StoredPasswordLookup + Send + Sync,
{
    stream: XmppStream<C, P>,
    info: StreamInfo,
    router: RouterHandle,
    stanza_tx: Sender<Stanza>,
    stanza_rx: Receiver<Stanza>,
    store: S,
    negotiable_features: Vec<Box<dyn FeatureNegotiator<C, P> + Send + Sync>>,
    settings: InboundStreamSettings,
}

impl<C, P, S> InboundStream<C, P, S>
where
    C: Connection + Send,
    P: StreamParser<ReadHalf<C>> + Send,
    S: StoredPasswordLookup + Send + Sync + 'static,
{
    pub fn new(
        connection: C,
        router: RouterHandle,
        store: S,
        negotiable_features: Vec<Box<dyn FeatureNegotiator<C, P> + Send + Sync>>,
        settings: InboundStreamSettings,
    ) -> Self {
        let stream = XmppStream::new(connection);
        let mut info = StreamInfo::default();
        if stream.is_secure() {
            info.features.insert(StreamFeature::Tls);
        }
        let (stanza_tx, stanza_rx) = mpsc::channel(STANZA_CHANNEL_BUFFER_SIZE);

        InboundStream {
            stream,
            info,
            router,
            stanza_tx,
            stanza_rx,
            store,
            negotiable_features,
            settings,
        }
    }

    pub async fn handle(&mut self) {
        match self.inner_handle().await {
            Ok(()) => (),
            Err(error) => {
                let _ = self.handle_unrecoverable_error(error).await;
            }
        }
    }

    async fn inner_handle(&mut self) -> Result<(), Error> {
        self.exchange_stream_headers().await?;
        self.advertise_features().await?;

        loop {
            select! {
                frame = self.stream.reader().next() => {
                    match frame {
                        Some(Ok(Frame::XmlFragment(element))) => self.process_element(element).await?,
                        _ => {
                            // assume peer terminated stream
                            let _ = self.stream.writer().write_stream_close().await;
                            return Ok(());
                        }
                    }
                }
                Some(Stanza { element }) = self.stanza_rx.recv() => {
                    self.stream.writer().write_xml_element(&element).await?;
                }
            }
        }
    }

    async fn process_element(&mut self, element: Element) -> Result<(), Error> {
        for feature in &self.negotiable_features {
            if let Ok(true) = dbg!(
                feature
                    .negotiate_feature(&element, &mut self.stream, &mut self.info)
                    .await
            ) {
                if feature.requires_restart() {
                    self.stream.reset();
                    self.exchange_stream_headers().await?;
                }

                self.advertise_features().await?;

                return Ok(());
            }
        }

        // TODO: handle unexpected non-stanza elements
        // TODO: don't route stanzas until allowed by features
        self.router
            .stanzas
            .send(Stanza { element })
            .await
            .map_err(|_| anyhow!("failed to route stanza"))
    }

    async fn register_peer_jid(&mut self, peer_jid: Option<Jid>) {
        if let Some(entity) = self.info.peer_jid.take() {
            self.router
                .management
                .send(ManagementCommand::Unregister(entity))
                .await
                .unwrap();
        }

        self.info.peer_jid = peer_jid;

        if let Some(entity) = self.info.peer_jid.clone() {
            self.router
                .management
                .send(ManagementCommand::Register(entity, self.stanza_tx.clone()))
                .await
                .unwrap();
        }
    }

    async fn advertise_features(&mut self) -> Result<(), Error> {
        let mut features = Element::new("features", Some(namespaces::XMPP_STREAMS));

        for feature in &self.negotiable_features {
            if let Some(advertised_feature) = feature.advertise_feature(&self.info) {
                features.add_child(advertised_feature);
            }
        }

        self.stream.writer().write_xml_element(&features).await
    }

    async fn exchange_stream_headers(&mut self) -> Result<(), Error> {
        let Ok(frame) = self
            .stream
            .reader()
            .next()
            .await
            .ok_or(anyhow!("stream closed by peer"))?
        else {
            self.send_stream_header(None).await?;
            self.handle_unrecoverable_error(anyhow!("expected xml frame"))
                .await?;
            bail!("expected xml frame");
        };

        let Frame::StreamStart(inbound_header) = frame else {
            self.send_stream_header(None).await?;
            self.handle_unrecoverable_error(anyhow!("expected stream header"))
                .await?;
            bail!("expected stream header");
        };

        self.info.jid = inbound_header.to; // TODO: make sure this only contains the domain part
        if let ConnectionType::Client = self.stream.connection_type() {
            self.info.peer_jid = self.info.jid.clone(); // TODO: why is this correct? what is the difference between jid and peer_jid?
        }
        self.info.peer_language = inbound_header.language;

        self.send_stream_header(self.info.peer_jid.clone()).await
    }

    async fn send_stream_header(&mut self, to: Option<Jid>) -> Result<(), Error> {
        let outbound_header = StreamHeader {
            from: Some(self.settings.domain.clone()),
            to,
            id: Some(self.info.stream_id.clone()),
            language: None,
        };

        self.stream
            .writer()
            .write_stream_header(&outbound_header, true)
            .await
    }

    async fn handle_unrecoverable_error(&mut self, error: Error) -> Result<(), Error> {
        dbg!(error);

        let mut error = Element::new("error", Some(namespaces::XMPP_STREAMS));
        error.with_child(
            "internal-server-error",
            Some(namespaces::XMPP_STREAM_ERRORS),
            |internal_server_error| {
                internal_server_error.set_attribute(
                    "xmlns",
                    None::<String>,
                    namespaces::XMPP_STREAM_ERRORS,
                );
            },
        );

        self.stream.writer().write_xml_element(&error).await?;
        self.stream.writer().write_stream_close().await
    }
}

#[async_trait::async_trait]
pub trait FeatureNegotiator<C, P>
where
    C: Connection + Send,
    P: StreamParser<ReadHalf<C>> + Send,
{
    fn advertise_feature(&self, info: &StreamInfo) -> Option<Element>;
    async fn negotiate_feature(
        &self,
        element: &Element,
        stream: &mut XmppStream<C, P>,
        info: &mut StreamInfo,
    ) -> Result<bool, StreamError>;
    fn requires_restart(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        spawn,
    };

    use confidante_core::{
        xml::stream_parser::rusty_xml::RustyXmlStreamParser,
        xmpp::stream::{ConnectionType, fake::FakeConnection},
    };
    use sasl::StoredPasswordLookup;

    use super::*;

    // TODO: move to sasl module?
    #[derive(Debug, Clone)]
    struct FakeStoredPasswordLookup;

    impl StoredPasswordLookup for FakeStoredPasswordLookup {
        async fn get_stored_password_argon2(&self, _jid: Jid) -> Result<String, anyhow::Error> {
            Ok("".to_string())
        }

        async fn get_stored_password_scram_sha1(&self, _jid: Jid) -> Result<String, anyhow::Error> {
            Ok("".to_string())
        }

        async fn get_stored_password_scram_sha256(
            &self,
            _jid: Jid,
        ) -> Result<String, anyhow::Error> {
            Ok("".to_string())
        }
    }

    #[tokio::test]
    async fn stream_features_empty_if_no_feature_is_provided() {
        let (mut client, server) = duplex(1000);
        let connection = FakeConnection::new(server, ConnectionType::Client);
        let mut stream = InboundStream::<_, RustyXmlStreamParser<_>, _>::new(
            connection,
            RouterHandle::default(),
            FakeStoredPasswordLookup,
            Vec::new(),
            InboundStreamSettings {
                domain: Jid::new(None, "example.com".to_string(), None),
            },
        );

        spawn(async move { stream.handle().await });
        client.write_all(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.com'></stream:stream>").await.unwrap();
        let mut buffer = String::new();
        client.read_to_string(&mut buffer).await.unwrap();

        assert!(buffer.contains("<stream:features/>"));
    }

    #[tokio::test]
    async fn stream_features_not_empty_if_a_feature_is_provided() {
        let (mut client, server) = duplex(1000);
        let connection = FakeConnection::new(server, ConnectionType::Client);
        let starttls: Box<dyn FeatureNegotiator<_, RustyXmlStreamParser<_>> + Send + Sync> =
            Box::new(starttls::StarttlsNegotiator::new());
        let mut stream = InboundStream::<_, RustyXmlStreamParser<_>, _>::new(
            connection,
            RouterHandle::default(),
            FakeStoredPasswordLookup,
            vec![starttls],
            InboundStreamSettings {
                domain: Jid::new(None, "example.com".to_string(), None),
            },
        );

        spawn(async move { stream.handle().await });
        client.write_all(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.com'></stream:stream>").await.unwrap();
        let mut buffer = String::new();
        client.read_to_string(&mut buffer).await.unwrap();

        assert!(buffer.contains("starttls"));
    }
}
