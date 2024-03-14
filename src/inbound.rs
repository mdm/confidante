use std::collections::HashMap;

use anyhow::{anyhow, Error};
use futures::stream;
use tokio::{io::AsyncWrite, net::TcpStream};
use tokio_stream::StreamExt;

use crate::xml::namespaces;
use crate::xmpp::jid::Jid;
use crate::xmpp::stream_header::{StreamHeader, StreamId};
use crate::{
    settings::Settings,
    xml::{
        stream_parser::{Frame, StreamParser},
        stream_writer::StreamWriter,
        Element, Node,
    },
};

use self::sasl::SaslNegotiator;
use bind::ResourceBindingNegotiator;

mod bind;
mod connection;
mod sasl;
mod tls;

enum State {
    Connected(StreamId), // TODO: do we need a consumable token here?
    Secured(StreamId),   // TODO: do we need the proof token here?
    Authenticated(StreamId, Jid),
    Bound(StreamId, Jid),
}

pub struct InboundStreamNegotiator<'s> {
    settings: &'s Settings,
}

// TODO: rename to InboundStreamNegotiator and feed Result<Frame>s instead of encapsulating the socket
impl<'s> InboundStreamNegotiator<'s> {
    pub fn new(settings: &'s Settings) -> Self {
        Self { settings }
    }

    pub async fn run<P: StreamParser, W: AsyncWrite + Unpin>(
        &mut self,
        stream_parser: &mut P,
        stream_writer: &mut StreamWriter<W>,
    ) -> Option<Jid> {
        let mut state = State::Connected(StreamId::new());

        loop {
            // TODO: handle timeouts while waiting for next frame
            state = match state {
                State::Connected(stream_id) => {
                    let Ok(frame) = stream_parser.next().await? else {
                        self.send_stream_header(stream_writer, None, stream_id)
                            .await
                            .ok()?;
                        self.handle_unrecoverable_error(
                            stream_writer,
                            anyhow!("expected xml frame"),
                        )
                        .await
                        .ok()?;
                        return None;
                    };

                    // TODO: check "stream" namespace here or in parser?

                    let Frame::StreamStart(inbound_header) = frame else {
                        self.send_stream_header(stream_writer, None, stream_id)
                            .await
                            .ok()?;
                        self.handle_unrecoverable_error(
                            stream_writer,
                            anyhow!("expected stream header"),
                        )
                        .await
                        .ok()?;
                        return None;
                    };

                    // TODO: check if `to` is a valid domain for this server

                    self.send_stream_header(stream_writer, inbound_header.from, stream_id)
                        .await
                        .ok()?;

                    if self.settings.tls.required_for_clients {
                        todo!();
                        State::Secured(stream_id)
                    } else {
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
                            .authenticate(stream_parser, stream_writer, false, false)
                            .await
                            .ok()?;
                        dbg!(&authenticated_entity);
                        State::Authenticated(StreamId::new(), authenticated_entity)
                    }
                }
                State::Secured(stream_id) => {
                    todo!()
                }
                State::Authenticated(stream_id, entity) => {
                    let Ok(frame) = stream_parser.next().await? else {
                        self.send_stream_header(stream_writer, None, stream_id)
                            .await
                            .ok()?;
                        self.handle_unrecoverable_error(
                            stream_writer,
                            anyhow!("expected xml frame"),
                        )
                        .await
                        .ok()?;
                        return None;
                    };

                    // TODO: check "stream" namespace here or in parser?

                    let Frame::StreamStart(inbound_header) = frame else {
                        self.send_stream_header(stream_writer, None, stream_id)
                            .await
                            .ok()?;
                        self.handle_unrecoverable_error(
                            stream_writer,
                            anyhow!("expected stream header"),
                        )
                        .await
                        .ok()?;
                        return None;
                    };

                    // TODO: check if `to` is a valid domain for this server

                    self.send_stream_header(stream_writer, inbound_header.from, stream_id.clone())
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
                        .bind_resource(stream_parser, stream_writer, &entity)
                        .await
                        .ok()?;
                    State::Bound(stream_id, bound_entity)
                }
                State::Bound(stream_id, bound_entity) => {
                    dbg!(&bound_entity);
                    // TODO: return stream info
                    return Some(bound_entity);
                }
            }
        }
    }

    async fn send_stream_header<W: AsyncWrite + Unpin>(
        &mut self,
        stream_writer: &mut StreamWriter<W>,
        to: Option<Jid>,
        stream_id: StreamId,
    ) -> Result<(), Error> {
        let outbound_header = StreamHeader {
            from: Some(self.settings.domain.clone()),
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
