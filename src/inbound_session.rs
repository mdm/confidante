mod bind;
mod connection;
mod sasl;
mod session;
mod tls;

use anyhow::{bail, Error};
use tokio::net::TcpStream;

use crate::{settings::Settings, inbound_session::bind::ResourceBindingNegotiator};

use bind::BoundResource;
use self::sasl::{AuthenticatedEntity, SaslNegotiator};
use session::Session;

enum InboundSessionState {
    Connected, // TODO: do we need a consumable token here?
    Secured, // TODO: do we need the proof token here?
    Authenticated(AuthenticatedEntity),
    Bound(BoundResource),
}

pub struct InboundSession {
    session: Session,
    state: InboundSessionState,
}

impl InboundSession {
    pub fn from_socket(socket: TcpStream, settings: Settings) -> Self {
        let session = Session::from_socket(socket, settings);
        let state = InboundSessionState::Connected;

        Self { session, state }
    }

    pub async fn handle(&mut self) -> Result<(), Error> {
        loop {
            match &self.state {
                InboundSessionState::Connected => {
                    let to = self.session.receive_stream_header().await?;
                    self.session.send_stream_header(&to, true).await?;

                    if self.session.settings.tls.required_for_clients {
                        todo!();
                    } else {
                        let sasl = SaslNegotiator::new();
                        self.session.write_bytes("<stream:features>\n".as_bytes()).await?;
                        sasl.advertise_feature(&mut self.session).await?;
                        // TODO: advertise voluntary-to-negotiate features
                        self.session.write_bytes("</stream:features>\n".as_bytes()).await?;
                        let authenticated_entity = sasl.authenticate(&mut self.session).await?;
                        dbg!(&authenticated_entity);
                        self.state = InboundSessionState::Authenticated(authenticated_entity);
                    }
                }
                InboundSessionState::Secured => {
                    todo!();
                }
                InboundSessionState::Authenticated(entity) => {
                    let to = self.session.receive_stream_header().await?;
                    self.session.send_stream_header(&to, true).await?;

                    let bind = ResourceBindingNegotiator::new();
                    self.session.write_bytes("<stream:features>\n".as_bytes()).await?;
                    bind.advertise_feature(&mut self.session).await?;
                    // TODO: advertise voluntary-to-negotiate features
                    self.session.write_bytes("</stream:features>\n".as_bytes()).await?;
                    let bound_resource = bind.bind_resource(entity, &mut self.session).await?;
                    dbg!(&bound_resource);
                    self.state = InboundSessionState::Bound(bound_resource);
                }
                InboundSessionState::Bound(resource) => {
                    dbg!(resource);
                    let next_frame = self.session.read_frame().await?;
                    dbg!(next_frame);
                }
            }
        }

        Ok(())
    }

    pub async fn handle_unrecoverable_error(&mut self, error: Error) {
        dbg!(error);

        self.session.write_bytes(r#"<stream:error>
    <internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>
</stream:error>"#.as_bytes()).await; // TODO: add proper error handling and handle error during error delivery
    }

    pub async fn close_stream(&mut self) {
        self.session.write_bytes("</stream:stream>".as_bytes()).await; // TODO: handle error during close tag delivery
    }
}
