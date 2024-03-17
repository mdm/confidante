mod inbound; // TODO: rename to inbound
mod services;
mod settings;
mod types;
mod utils;
mod xml;
mod xmpp;

use std::path::Path;
use std::str::FromStr;

use quick_xml::reader;
use rustyxml::Element;
use tokio::select;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use uuid::Uuid;

use inbound::InboundStreamNegotiator;
use services::router::{ManagementCommand, RouterHandle};
use settings::Settings;
use utils::recorder::StreamRecorder;
use xml::stream_parser::Frame;
use xml::stream_parser::{rusty_xml::StreamParser as ConcreteStreamParser, StreamParser};
use xml::stream_writer::StreamWriter;
use xmpp::stanza::Stanza;

use crate::xmpp::jid::Jid;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let settings = Settings::new()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5222").await?;

    let router_handle = RouterHandle::new();

    loop {
        let (socket, _) = listener.accept().await?;
        let settings = settings.clone();

        // TODO: handle shutdown

        let router_handle = router_handle.clone();

        tokio::spawn(async move {
            let mut inbound_negotiator = InboundStreamNegotiator::new(&settings);

            let (reader, writer) = tokio::io::split(socket);
            let log_id = Uuid::new_v4();
            println!("New connection: {}", log_id);
            let reader = StreamRecorder::try_new(reader, log_id).await.unwrap();
            let writer = StreamRecorder::try_new(writer, log_id).await.unwrap();

            let mut stream_parser = ConcreteStreamParser::new(reader);
            let mut stream_writer = StreamWriter::new(writer);

            if let Some(entity) = inbound_negotiator
                .run(&mut stream_parser, &mut stream_writer)
                .await
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
