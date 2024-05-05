mod inbound; // TODO: rename to inbound
mod services;
mod settings;
mod types;
mod utils;
mod xml;
mod xmpp;

use tokio::select;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use inbound::connection::debug::DebugConnection;
use inbound::connection::tcp::TcpConnection;
use inbound::InboundStreamNegotiator;
use services::router::{ManagementCommand, RouterHandle};
use settings::Settings;
use xml::stream_parser::Frame;
use xmpp::stanza::Stanza;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    Settings::init()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5222").await?;

    let router_handle = RouterHandle::new();

    loop {
        let (socket, _) = listener.accept().await?;

        // TODO: handle shutdown

        let router_handle = router_handle.clone();

        tokio::spawn(async move {
            let mut inbound_negotiator = InboundStreamNegotiator::new();

            let socket = TcpConnection::new(socket, true);

            let socket = DebugConnection::try_new(socket).await.unwrap();
            println!("New connection: {}", socket.uuid());

            if let Some((entity, mut stream_parser, mut stream_writer)) =
                inbound_negotiator.run(socket).await
            {
                let (entity_tx, mut entity_rx) = mpsc::channel(8);
                router_handle
                    .management
                    .send(ManagementCommand::Register(entity, entity_tx))
                    .await
                    .unwrap();

                loop {
                    select! {
                        Some(Ok(Frame::XmlFragment(element))) = stream_parser.next() => {
                            router_handle.stanzas.send(Stanza { element }).await.unwrap();
                        }
                        Some(Stanza { element }) = entity_rx.recv() => {
                            stream_writer.write_xml_element(&element).await.unwrap();
                        }
                    }
                }
            }

            // TODO: close connection (or does drop do that?)
            // let reader = stream_parser.into_inner();
            // reader.into_inner().shutdown(std::net::Shutdown::Both).unwrap();
        });
    }
}
