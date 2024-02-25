mod bind;
mod connection;
mod sasl;
mod tls;

use std::collections::HashMap;

use anyhow::{bail, Error};
use tokio::{io::AsyncWrite, net::TcpStream};
use tokio_stream::StreamExt;

use crate::xml::namespaces;
use crate::xmpp::stream_header::{StreamHeader, StreamId};
use crate::{
    settings::Settings,
    xml::{
        stream_parser::{Frame, StreamParser},
        stream_writer::StreamWriter,
        Element, Node,
    },
};

use self::sasl::{AuthenticatedEntity, SaslNegotiator};
use bind::{BoundResource, ResourceBindingNegotiator};

enum State {
    Connected, // TODO: do we need a consumable token here?
    Secured,   // TODO: do we need the proof token here?
    Authenticated(AuthenticatedEntity, bool),
    Bound(BoundResource),
}

pub struct InboundStreamNegotiator<'s> {
    settings: &'s Settings,
    state: State,
    stream_id: StreamId,
}

// TODO: rename to InboundStreamNegotiator and feed Result<Frame>s instead of encapsulating the socket
impl<'s> InboundStreamNegotiator<'s> {
    pub fn new(settings: &'s Settings) -> Self {
        let state = State::Connected;
        let stream_id = StreamId::new();

        Self {
            settings,
            state,
            stream_id,
        }
    }

    pub async fn run<P: StreamParser, W: AsyncWrite + Unpin>(
        &mut self,
        stream_parser: &mut P,
        stream_writer: &mut StreamWriter<W>,
    ) -> Result<(), Error> {
        loop {
            // TODO: handle timeouts while waiting for next frame
            match &self.state {
                State::Connected => {
                    let Some(Ok(frame)) = stream_parser.next().await else {
                        bail!("expected xml frame");
                    };

                    // TODO: check "stream" namespace here or in parser?

                    let Frame::StreamStart(inbound_header) = frame else {
                        bail!("expected stream header");
                    };

                    // TODO: check if `to` is a valid domain for this server

                    let outbound_header = StreamHeader {
                        from: Some(self.settings.domain.clone()),
                        to: inbound_header.from,
                        id: Some(self.stream_id.clone()),
                        language: None,
                    };

                    stream_writer
                        .write_stream_header(&outbound_header, true)
                        .await?;

                    if self.settings.tls.required_for_clients {
                        todo!();
                    } else {
                        let mut sasl = SaslNegotiator::new();
                        let features = Element {
                            name: "features".to_string(),
                            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
                            attributes: HashMap::new(),
                            children: vec![Node::Element(sasl.advertise_feature(false, false))], // TODO: advertise voluntary-to-negotiate features
                        };
                        stream_writer.write_xml_element(&features).await?;

                        let authenticated_entity = sasl
                            .authenticate(stream_parser, stream_writer, false, false)
                            .await?;
                        dbg!(&authenticated_entity);
                        self.state = State::Authenticated(authenticated_entity, false);
                    }
                }
                State::Secured => {
                    todo!();
                }
                State::Authenticated(entity, secure) => {
                    let Some(Ok(frame)) = stream_parser.next().await else {
                        bail!("expected xml frame");
                    };

                    // TODO: check "stream" namespace here or in parser?

                    let Frame::StreamStart(inbound_header) = frame else {
                        bail!("expected stream header");
                    };

                    // TODO: check if `to` is a valid domain for this server

                    let outbound_header = StreamHeader {
                        from: Some(self.settings.domain.clone()),
                        to: inbound_header.from,
                        id: Some(self.stream_id.clone()),
                        language: None,
                    };

                    stream_writer
                        .write_stream_header(&outbound_header, true)
                        .await?;

                    let bind = ResourceBindingNegotiator::new();
                    let features = Element {
                        name: "features".to_string(),
                        namespace: Some(namespaces::XMPP_STREAMS.to_string()),
                        attributes: HashMap::new(),
                        children: vec![Node::Element(bind.advertise_feature())], // TODO: advertise voluntary-to-negotiate features
                    };
                    stream_writer.write_xml_element(&features).await?;

                    let bound_resource = bind.bind_resource(stream_parser, stream_writer, entity).await?;
                    dbg!(&bound_resource);
                    self.state = State::Bound(bound_resource);
                }
                State::Bound(resource) => {
                    dbg!(resource);
                    let next_frame = stream_parser.next().await.transpose()?;
                    dbg!(next_frame);
                    return Ok(());
                }
            }
        }
    }

    pub async fn handle_unrecoverable_error<W: AsyncWrite + Unpin>(
        &mut self,
        stream_writer: &mut StreamWriter<W>,
        error: Error,
    ) {
        dbg!(error);

        let error = Element {
            name: "error".to_string(),
            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
            attributes: HashMap::new(),
            children: vec![Node::Element(Element {
                name: "internal-server-error".to_string(),
                namespace: Some(namespaces::XMPP_STREAM_ERRORS.to_string()),
                attributes: HashMap::new(),
                children: vec![],
            })],
        };

        stream_writer.write_xml_element(&error).await; // TODO: add proper error handling and handle error during error delivery
    }

    pub async fn close_stream<W: AsyncWrite + Unpin>(
        &mut self,
        stream_writer: &mut StreamWriter<W>,
    ) {
        stream_writer.write_stream_close().await; // TODO: handle error during close tag delivery
    }
}
