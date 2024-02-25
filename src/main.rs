mod inbound; // TODO: rename to inbound
mod xmpp;
mod settings;
mod types;
mod xml;

use inbound::InboundStreamNegotiator;
use settings::Settings;
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

            // TODO: handle constructors for parser and writer in the same way
            let mut stream_parser = ConcreteStreamParser::new(reader);
            let mut stream_writer = StreamWriter::new(writer);

            if let Err(err) = inbound_negotiator.run(&mut stream_parser, &mut stream_writer).await {
                // TODO: move error handling out of negotiator
                inbound_negotiator.handle_unrecoverable_error(&mut stream_writer, err).await;
            }

            // TODO: move stream closing out of negotiator
            inbound_negotiator.close_stream(&mut stream_writer).await;
        });
    }
}
