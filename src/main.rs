mod inbound; // TODO: rename to inbound
mod settings;
mod types;
mod utils;
mod xml;
mod xmpp;

use std::path::Path;

use uuid::Uuid;

use inbound::InboundStreamNegotiator;
use settings::Settings;
use utils::recorder::StreamRecorder;
use xml::stream_parser::{rusty_xml::StreamParser as ConcreteStreamParser, StreamParser};
use xml::stream_writer::StreamWriter;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let settings = Settings::new()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5222").await?;

    loop {
        let (socket, _) = listener.accept().await?;
        let settings = settings.clone();

        // TODO: handle shutdown

        tokio::spawn(async move {
            let mut inbound_negotiator = InboundStreamNegotiator::new(&settings);

            let (reader, writer) = tokio::io::split(socket);
            let log_id = Uuid::new_v4();
            println!("New connection: {}", log_id);
            let reader = StreamRecorder::try_new(reader, &log_id).await.unwrap();
            let writer = StreamRecorder::try_new(writer, &log_id).await.unwrap();

            // TODO: handle constructors for parser and writer in the same way
            let mut stream_parser = ConcreteStreamParser::new(reader);
            let mut stream_writer = StreamWriter::new(writer);

            if let Err(err) = inbound_negotiator
                .run(&mut stream_parser, &mut stream_writer)
                .await
            {
                // TODO: move error handling out of negotiator
                inbound_negotiator
                    .handle_unrecoverable_error(&mut stream_writer, err)
                    .await;
            }

            // TODO: move stream closing out of negotiator
            inbound_negotiator.close_stream(&mut stream_writer).await;
        });
    }
}
