use std::collections::HashMap;
use std::collections::HashSet;

use anyhow::{anyhow, bail, Error};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::StreamExt;

use crate::services::router::ManagementCommand;
use crate::services::router::RouterHandle;
use crate::xml::namespaces;
use crate::xmpp::jid::Jid;
use crate::xmpp::stanza::Stanza;
use crate::xmpp::stream::Connection;
use crate::xmpp::stream::StreamId;
use crate::xmpp::stream::XmppStream;
use crate::xmpp::stream_header::LanguageTag;
use crate::xmpp::stream_header::StreamHeader;
use crate::{
    settings::get_settings,
    xml::{stream_parser::Frame, Element, Node},
};

use self::sasl::SaslNegotiator;
use bind::ResourceBindingNegotiator;
use starttls::StarttlsNegotiator;

mod bind;
pub mod connection;
mod sasl;
mod starttls;

const STANZA_CHANNEL_BUFFER_SIZE: usize = 8;

enum State {
    Connected(StreamId),     // TODO: do we need a consumable token here?
    Secured(StreamId, bool), // TODO: do we need the proof token here?
    Authenticated(StreamId, Jid),
    Bound(StreamId, Jid),
}

enum ConnectionType {
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
    connection_type: Option<ConnectionType>, // TODO: move to Connection. Depends on port only.
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

pub struct InboundStream<C>
where
    C: Connection,
{
    stream: XmppStream<C>,
    info: StreamInfo,
    router_handle: RouterHandle,
    stanza_tx: Sender<Stanza>,
    stanza_rx: Receiver<Stanza>,
}

impl<C> InboundStream<C>
where
    C: Connection,
{
    pub fn new(connection: C, router_handle: RouterHandle) -> Self {
        let stream = XmppStream::new(connection);
        let info = StreamInfo::default();
        let (stanza_tx, stanza_rx) = mpsc::channel(STANZA_CHANNEL_BUFFER_SIZE);

        InboundStream {
            stream,
            info,
            router_handle,
            stanza_tx,
            stanza_rx,
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
                        // TODO: handle parser errors
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
                // TODO: handle connection timeouts here
            }
        }
    }

    async fn process_element(&mut self, element: Element) -> Result<(), Error> {
        for feature in self.negotiable_features() {
            if let Ok(()) = dbg!(self.negotiate_feature(feature, &element).await) {
                return Ok(());
            }
            // TODO: if tag matched the feature but negotiation failed, return error here
        }

        // TODO: filter out unsupported features

        // element must be a stanza at this point
        //TODO: respond with not-authorized target is not yet cleared to send stanzas
        //TODO: respond with not-authorized if not authenticated

        self.router_handle
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

        let tls_required = match self.info.connection_type {
            Some(ConnectionType::Client) => get_settings().tls.required_for_clients,
            Some(ConnectionType::Server) => get_settings().tls.required_for_servers,
            None => false,
        };
        if (!tls_required || self.info.features.contains(&StreamFeatures::Tls))
            && !self.info.features.contains(&StreamFeatures::Authentication)
        {
            features.push(StreamFeatures::Authentication);
        }

        if let Some(ConnectionType::Client) = self.info.connection_type {
            if self.info.features.contains(&StreamFeatures::Authentication)
                && !self
                    .info
                    .features
                    .contains(&StreamFeatures::ResourceBinding)
            {
                features.push(StreamFeatures::ResourceBinding);
            }
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
                let peer_jid =
                    Some(SaslNegotiator::negotiate_feature(&mut self.stream, element).await?);
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
            self.router_handle
                .management
                .send(ManagementCommand::Unregister(entity))
                .await
                .unwrap(); // TODO: handle error
        }

        self.info.peer_jid = peer_jid;

        if let Some(entity) = self.info.peer_jid.clone() {
            self.router_handle
                .management
                .send(ManagementCommand::Register(entity, self.stanza_tx.clone()))
                .await
                .unwrap(); // TODO: handle error
        }
    }

    async fn advertise_features(&mut self) -> Result<(), Error> {
        let features = self
            .negotiable_features()
            .into_iter()
            .map(|feature| match feature {
                StreamFeatures::Tls => Node::Element(StarttlsNegotiator::advertise_feature()),
                StreamFeatures::Authentication => Node::Element(SaslNegotiator::advertise_feature(
                    self.stream.is_secure(),
                    self.stream.is_authenticated(),
                )),
                StreamFeatures::ResourceBinding => {
                    Node::Element(ResourceBindingNegotiator::advertise_feature())
                }
            })
            .collect();

        let features = Element {
            name: "features".to_string(),
            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
            attributes: HashMap::new(),
            children: features,
        };

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

        // TODO: check "stream" namespace here or in parser?

        let Frame::StreamStart(inbound_header) = frame else {
            self.send_stream_header(None).await?;
            self.handle_unrecoverable_error(anyhow!("expected stream header"))
                .await?;
            bail!("expected stream header");
        };

        // TODO: check if `to` is a valid domain for this server (and do virtual hosting resolution here?)
        // TODO: only accept new header attributes if they are not already set

        self.info.jid = inbound_header.to;
        self.info.peer_language = inbound_header.language;
        self.info.connection_type = Some(ConnectionType::Client); // TODO: don't hardcode this

        self.send_stream_header(self.info.peer_jid.clone()).await
    }

    async fn send_stream_header(&mut self, to: Option<Jid>) -> Result<(), Error> {
        // TODO: unify StreamInfo and StreamHeader? Or is there benefit in keeping them separate?
        let outbound_header = StreamHeader {
            from: Some(get_settings().domain.clone()),
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

        let error = Element {
            name: "error".to_string(),
            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
            attributes: HashMap::new(),
            children: vec![Node::Element(Element {
                name: "internal-server-error".to_string(),
                namespace: Some(namespaces::XMPP_STREAM_ERRORS.to_string()),
                attributes: vec![(
                    ("xmlns".to_string(), None),
                    namespaces::XMPP_STREAM_ERRORS.to_string(),
                )]
                .into_iter()
                .collect(),
                children: vec![],
            })],
        };

        self.stream.writer().write_xml_element(&error).await?; // TODO: add proper error handling and handle error during error delivery
        self.stream.writer().write_stream_close().await
    }
}
