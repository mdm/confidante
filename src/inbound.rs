use std::collections::HashMap;

use anyhow::{anyhow, bail, Error};
use tokio::io::AsyncWrite;
use tokio::io::WriteHalf;
use tokio_stream::StreamExt;

use crate::xml::namespaces;
use crate::xml::stream_parser::rusty_xml::StreamParser as ConcreteStreamParser;
use crate::xmpp::jid::Jid;
use crate::xmpp::stream_header::StreamHeader;
use crate::xmpp::StreamId;
use crate::{
    settings::get_settings,
    xml::{
        stream_parser::{Frame, StreamParser},
        stream_writer::StreamWriter,
        Element, Node,
    },
};

use self::connection::Connection;
use self::sasl::SaslNegotiator;
use bind::ResourceBindingNegotiator;
use starttls::StarttlsNegotiator;

mod bind;
pub mod connection;
mod sasl;
mod starttls;

enum State {
    Connected(StreamId),     // TODO: do we need a consumable token here?
    Secured(StreamId, bool), // TODO: do we need the proof token here?
    Authenticated(StreamId, Jid),
    Bound(StreamId, Jid),
}

pub struct InboundStreamNegotiator {
    _private: (),
}

// TODO: rename to InboundStreamNegotiator and feed Result<Frame>s instead of encapsulating the socket
impl InboundStreamNegotiator {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub async fn run<C: Connection>(
        &mut self,
        socket: C,
    ) -> Option<(Jid, impl StreamParser, StreamWriter<WriteHalf<C>>)> {
        // TODO: return Result instead of Option, to be able to close connection without closing the stream on TLS handshake error
        let starttls_allowed = socket.is_starttls_allowed();
        let (reader, writer) = tokio::io::split(socket);
        let mut stream_parser = ConcreteStreamParser::new(reader);
        let mut stream_writer = StreamWriter::new(writer);

        let mut state = State::Connected(StreamId::new()); // TODO: start in Secured state if socket is already secure

        loop {
            // TODO: handle timeouts while waiting for next frame
            state = match state {
                State::Connected(stream_id) => {
                    // TODO: DRY up stream header exchange
                    self.exchange_stream_headers(
                        stream_id.clone(),
                        &mut stream_parser,
                        &mut stream_writer,
                    )
                    .await
                    .ok()?;

                    if get_settings().tls.required_for_clients && starttls_allowed {
                        let starttls = StarttlsNegotiator::new();
                        let features = Element {
                            name: "features".to_string(),
                            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
                            attributes: HashMap::new(),
                            children: vec![Node::Element(starttls.advertise_feature())], // TODO: advertise voluntary-to-negotiate features
                        };
                        dbg!(&features);
                        stream_writer.write_xml_element(&features).await.ok()?;

                        let secure_socket =
                            starttls.starttls(stream_parser, stream_writer).await.ok()?;
                        let authenticated = secure_socket.is_authenticated(); // TODO: check authenticated entity

                        let (reader, writer) = tokio::io::split(secure_socket);
                        stream_parser = ConcreteStreamParser::new(reader);
                        stream_writer = StreamWriter::new(writer);

                        State::Secured(stream_id, authenticated)
                    } else {
                        // TODO: allow negotiating STARTTLS voluntarily
                        let mut sasl = SaslNegotiator::new();
                        let features = Element {
                            name: "features".to_string(),
                            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
                            attributes: HashMap::new(),
                            children: vec![Node::Element(sasl.advertise_feature(false, false))], // TODO: advertise voluntary-to-negotiate features
                        };
                        dbg!(&features);
                        stream_writer.write_xml_element(&features).await.ok()?;

                        let authenticated_entity = sasl
                            .authenticate(&mut stream_parser, &mut stream_writer, false, false)
                            .await
                            .ok()?;
                        dbg!(&authenticated_entity);
                        State::Authenticated(StreamId::new(), authenticated_entity)
                    }
                }
                State::Secured(stream_id, authenticated) => {
                    self.exchange_stream_headers(stream_id, &mut stream_parser, &mut stream_writer)
                        .await
                        .ok()?;

                    let mut sasl = SaslNegotiator::new();
                    let features = Element {
                        name: "features".to_string(),
                        namespace: Some(namespaces::XMPP_STREAMS.to_string()),
                        attributes: HashMap::new(),
                        children: vec![Node::Element(sasl.advertise_feature(true, authenticated))], // TODO: advertise voluntary-to-negotiate features
                    };
                    dbg!(&features);
                    stream_writer.write_xml_element(&features).await.ok()?;

                    let authenticated_entity = sasl
                        .authenticate(&mut stream_parser, &mut stream_writer, true, authenticated)
                        .await
                        .ok()?;
                    dbg!(&authenticated_entity);
                    State::Authenticated(StreamId::new(), authenticated_entity)
                }
                State::Authenticated(stream_id, entity) => {
                    self.exchange_stream_headers(
                        stream_id.clone(),
                        &mut stream_parser,
                        &mut stream_writer,
                    )
                    .await
                    .ok()?;

                    let bind = ResourceBindingNegotiator::new();
                    let features = Element {
                        name: "features".to_string(),
                        namespace: Some(namespaces::XMPP_STREAMS.to_string()),
                        attributes: HashMap::new(),
                        children: vec![Node::Element(bind.advertise_feature())], // TODO: advertise voluntary-to-negotiate features
                    };
                    stream_writer.write_xml_element(&features).await.ok()?;

                    let bound_entity = bind
                        .bind_resource(&mut stream_parser, &mut stream_writer, &entity)
                        .await
                        .ok()?;
                    State::Bound(stream_id, bound_entity)
                }
                State::Bound(stream_id, bound_entity) => {
                    dbg!(&bound_entity);
                    // TODO: return stream info
                    return Some((bound_entity, stream_parser, stream_writer));
                }
            }
        }
    }

    async fn exchange_stream_headers<P, W>(
        &mut self,
        stream_id: StreamId,
        stream_parser: &mut P,
        stream_writer: &mut StreamWriter<W>,
    ) -> Result<(), Error>
    where
        P: StreamParser,
        W: AsyncWrite + Unpin,
    {
        let Ok(frame) = stream_parser
            .next()
            .await
            .ok_or(anyhow!("stream closed by peer"))?
        else {
            self.send_stream_header(stream_id, None, stream_writer)
                .await?;
            self.handle_unrecoverable_error(stream_writer, anyhow!("expected xml frame"))
                .await?;
            bail!("expected xml frame");
        };

        // TODO: check "stream" namespace here or in parser?

        let Frame::StreamStart(inbound_header) = frame else {
            self.send_stream_header(stream_id, None, stream_writer)
                .await?;
            self.handle_unrecoverable_error(stream_writer, anyhow!("expected stream header"))
                .await?;
            bail!("expected stream header");
        };

        // TODO: check if `to` is a valid domain for this server

        self.send_stream_header(stream_id, inbound_header.from, stream_writer)
            .await
    }

    async fn send_stream_header<W: AsyncWrite + Unpin>(
        &mut self,
        stream_id: StreamId,
        to: Option<Jid>,
        stream_writer: &mut StreamWriter<W>,
    ) -> Result<(), Error> {
        let outbound_header = StreamHeader {
            from: Some(get_settings().domain.clone()),
            to,
            id: Some(stream_id),
            language: None,
        };

        stream_writer
            .write_stream_header(&outbound_header, true)
            .await
    }

    async fn handle_unrecoverable_error<W: AsyncWrite + Unpin>(
        &mut self,
        stream_writer: &mut StreamWriter<W>,
        error: Error,
    ) -> Result<(), Error> {
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

        stream_writer.write_xml_element(&error).await?; // TODO: add proper error handling and handle error during error delivery
        stream_writer.write_stream_close().await
    }

    pub async fn close_stream<W: AsyncWrite + Unpin>(
        &mut self,
        stream_writer: &mut StreamWriter<W>,
    ) {
        stream_writer.write_stream_close().await; // TODO: handle error during close tag delivery
    }
}
