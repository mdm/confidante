mod bind;
mod connection;
mod sasl;
mod info;
mod tls;

use std::collections::HashMap;

use anyhow::{bail, Error};
use futures::Stream;
use tokio::{io::AsyncWrite, net::TcpStream};
use tokio_stream::StreamExt;

use crate::xml::namespaces;
use crate::xmpp::stream_header::{StreamHeader, StreamId};
use crate::{
    settings::Settings,
    xml::{
        Element,
        stream_parser::{Frame, StreamParser},
        stream_writer::StreamWriter,
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
    pub fn new(settings: &Settings) -> Self {
        let state = State::Connected;
        let stream_id = StreamId::new();

        Self { settings, state, stream_id }
    }

    pub async fn run<P: StreamParser, W: AsyncWrite>(
        &mut self,
        stream_parser: &mut P,
        writer: &mut W,
    ) -> Result<(), Error> {
        let writer = StreamWriter::new(writer);
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
                        from: Some(self.settings.domain),
                        to: inbound_header.from,
                        id: Some(self.stream_id),
                        language: None,
                    };

                    writer.write_stream_header(&outbound_header, true).await?;

                    if self.settings.tls.required_for_clients {
                        todo!();
                    } else {
                        let sasl = SaslNegotiator::new();
                        let features = Element {
                            name: "features".to_string(),
                            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
                            attributes: HashMap::new(),
                            children: vec![sasl.advertise_feature(false)],
                        };

                        // TODO: advertise voluntary-to-negotiate features

                        let authenticated_entity = sasl.authenticate(&mut self.session).await?;
                        dbg!(&authenticated_entity);
                        self.state = State::Authenticated(authenticated_entity, false);
                    }
                }
                State::Secured => {
                    todo!();
                }
                State::Authenticated(entity, secure) => {
                    let to = self.session.receive_stream_header().await?;
                    self.session.send_stream_header(&to, true).await?;

                    let bind = ResourceBindingNegotiator::new();
                    self.session
                        .write_bytes("<stream:features>\n".as_bytes())
                        .await?;
                    bind.advertise_feature(&mut self.session).await?;
                    // TODO: advertise voluntary-to-negotiate features
                    self.session
                        .write_bytes("</stream:features>\n".as_bytes())
                        .await?;
                    let bound_resource = bind.bind_resource(entity, &mut self.session).await?;
                    dbg!(&bound_resource);
                    self.state = State::Bound(bound_resource);
                }
                State::Bound(resource) => {
                    dbg!(resource);
                    let next_frame = self.session.read_frame().await?;
                    dbg!(next_frame);
                    return Ok(());
                }
            }
        }
    }

    pub async fn handle_unrecoverable_error(&mut self, error: Error) {
        dbg!(error);

        self.session
            .write_bytes(
                r#"<stream:error>
    <internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>
</stream:error>"#
                    .as_bytes(),
            )
            .await; // TODO: add proper error handling and handle error during error delivery
    }

    pub async fn close_stream(&mut self) {
        self.session
            .write_bytes("</stream:stream>".as_bytes())
            .await; // TODO: handle error during close tag delivery
    }
}
