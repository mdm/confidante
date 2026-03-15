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
use confidante_core::xmpp::stream::Connection;
use confidante_core::xmpp::stream::StreamId;
use confidante_core::xmpp::stream::XmppStream;
use confidante_core::xmpp::stream_header::LanguageTag;
use confidante_core::xmpp::stream_header::StreamHeader;
use confidante_services::router::ManagementCommand;
use confidante_services::router::RouterHandle;

use self::sasl::SaslNegotiator;
use bind::ResourceBindingNegotiator;
use starttls::StarttlsNegotiator;

mod bind;
pub mod connection;
pub mod sasl;
mod starttls;

const STANZA_CHANNEL_BUFFER_SIZE: usize = 8;

#[derive(Clone, Copy)]
pub enum ConnectionType {
    Client,
    Server,
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum StreamFeatures {
    Tls,
    Authentication,
    ResourceBinding,
}

struct StreamInfo {
    stream_id: StreamId,
    jid: Option<Jid>,
    peer_jid: Option<Jid>,
    peer_language: Option<LanguageTag>,
    connection_type: Option<ConnectionType>,
    features: HashSet<StreamFeatures>,
}

impl Default for StreamInfo {
    fn default() -> Self {
        StreamInfo {
            stream_id: StreamId::new(),
            jid: None,
            peer_jid: None,
            peer_language: None,
            connection_type: None,
            features: HashSet::new(),
        }
    }
}

pub struct InboundStreamSettings {
    pub connection_type: ConnectionType,
    pub domain: Jid,
    pub tls_required: bool,
}

pub struct InboundStream<C, P, S>
where
    C: Connection,
    P: StreamParser<ReadHalf<C>>,
    S: StoredPasswordLookup + Send + Sync,
{
    stream: XmppStream<C, P>,
    info: StreamInfo,
    router: RouterHandle,
    stanza_tx: Sender<Stanza>,
    stanza_rx: Receiver<Stanza>,
    store: S,
    settings: InboundStreamSettings,
}

impl<C, P, S> InboundStream<C, P, S>
where
    C: Connection,
    P: StreamParser<ReadHalf<C>>,
    S: StoredPasswordLookup + Send + Sync,
{
    pub fn new(
        connection: C,
        router: RouterHandle,
        store: S,
        settings: InboundStreamSettings,
    ) -> Self {
        let stream = XmppStream::new(connection);
        let info = StreamInfo::default();
        let (stanza_tx, stanza_rx) = mpsc::channel(STANZA_CHANNEL_BUFFER_SIZE);

        InboundStream {
            stream,
            info,
            router,
            stanza_tx,
            stanza_rx,
            store,
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
        for feature in self.negotiable_features() {
            if let Ok(()) = dbg!(self.negotiate_feature(feature, &element).await) {
                return Ok(());
            }
        }

        // element must be a stanza at this point
        self.router
            .stanzas
            .send(Stanza { element })
            .await
            .map_err(|_| anyhow!("failed to route stanza"))
    }

    fn negotiable_features(&self) -> Vec<StreamFeatures> {
        let mut features = vec![];

        if self.stream.is_starttls_allowed() && !self.info.features.contains(&StreamFeatures::Tls) {
            features.push(StreamFeatures::Tls);
        }

        if (!self.settings.tls_required || self.info.features.contains(&StreamFeatures::Tls))
            && !self.info.features.contains(&StreamFeatures::Authentication)
        {
            features.push(StreamFeatures::Authentication);
        }

        if let Some(ConnectionType::Client) = self.info.connection_type
            && self.info.features.contains(&StreamFeatures::Authentication)
            && !self
                .info
                .features
                .contains(&StreamFeatures::ResourceBinding)
        {
            features.push(StreamFeatures::ResourceBinding);
        }

        features
    }

    async fn negotiate_feature(
        &mut self,
        feature: StreamFeatures,
        element: &Element,
    ) -> Result<(), Error> {
        match feature {
            StreamFeatures::Tls => {
                StarttlsNegotiator::negotiate_feature(&mut self.stream, element).await?;
                self.info.features.insert(StreamFeatures::Tls);
                self.stream.reset();
                self.exchange_stream_headers().await?;
                self.advertise_features().await?;
            }
            StreamFeatures::Authentication => {
                let peer_jid = Some(
                    SaslNegotiator::negotiate_feature(
                        &mut self.stream,
                        element,
                        self.store.clone(),
                    )
                    .await?,
                );
                dbg!(&peer_jid);
                self.register_peer_jid(peer_jid).await;
                self.info.features.insert(StreamFeatures::Authentication);
                self.stream.reset();
                self.exchange_stream_headers().await?;
                self.advertise_features().await?;
            }
            StreamFeatures::ResourceBinding => {
                let peer_jid = Some(
                    ResourceBindingNegotiator::negotiate_feature(
                        &mut self.stream,
                        element,
                        &self.info.peer_jid,
                    )
                    .await?,
                );
                self.register_peer_jid(peer_jid).await;
                self.info.features.insert(StreamFeatures::ResourceBinding);
            }
        }

        Ok(())
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
        for feature in self.negotiable_features() {
            let feature = match feature {
                StreamFeatures::Tls => StarttlsNegotiator::advertise_feature(),
                StreamFeatures::Authentication => SaslNegotiator::advertise_feature(
                    self.stream.is_secure(),
                    self.stream.is_authenticated(),
                ),
                StreamFeatures::ResourceBinding => ResourceBindingNegotiator::advertise_feature(),
            };
            features.add_child(feature);
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

        self.info.jid = inbound_header.to;
        self.info.peer_language = inbound_header.language;
        self.info.connection_type = Some(self.settings.connection_type);

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
