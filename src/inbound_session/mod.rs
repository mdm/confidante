mod bind;
mod connection;
mod sasl;
mod session;
mod tls;

use anyhow::Error;
use tokio::net::TcpStream;

use crate::settings::Settings;

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
    sasl: SaslNegotiator,
    session: Session,
    state: InboundSessionState,
}

impl InboundSession {
    pub fn from_socket(socket: TcpStream, settings: Settings) -> Self {
        let sasl = SaslNegotiator::new();
        let session = Session::from_socket(socket, settings);
        let state = InboundSessionState::Connected;

        Self { sasl, session, state }
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
                        self.session.write_bytes("<stream:features>\n".as_bytes()).await?;
                        self.sasl.advertise_feature(&mut self.session).await?;
                        self.session.write_bytes("</stream:features>\n".as_bytes()).await?;
                        let authenticated_entity = self.sasl.authenticate(&mut self.session).await?;
                        dbg!("after auth");
                        self.state = InboundSessionState::Authenticated(authenticated_entity);
                    }
                }
                InboundSessionState::Secured => {
                    todo!();
                }
                InboundSessionState::Authenticated(entity) => {
                    dbg!(entity);
                    let next_frame = self.session.read_frame().await?;
                    dbg!(next_frame);
                    break;                    
                }
                InboundSessionState::Bound(resource) => {
                    todo!();
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
