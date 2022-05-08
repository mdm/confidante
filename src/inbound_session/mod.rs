mod connection;
mod sasl;

use rand::{RngCore, SeedableRng};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::settings::Settings;
use crate::xml_stream_parser::{XmlFrame, XmlStreamParser};

use connection::Connection;
use self::sasl::SaslNegotiator;

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct InboundSession {
    connection: Connection,
    parser: XmlStreamParser,
    sasl: SaslNegotiator,
    settings: Settings,
}

impl InboundSession {
    pub fn from_socket(socket: TcpStream, settings: Settings) -> Self {
        let connection = Connection::from_socket(socket);
        let parser = XmlStreamParser::new();
        let sasl = SaslNegotiator::new();

        Self { connection, parser, sasl, settings }
    }

    pub async fn handle(&mut self) {
        loop {
            match self.parser.next_frame(&mut self.connection.socket()).await {
                Ok(Some(XmlFrame::StreamStart(initial_stream_header))) => {
                    if let Some(to) = initial_stream_header.attributes.get(&("to".into(), None)) {
                        if let Err(_err) = self.send_stream_header(to, true).await {
                            break;
                        }

                        if let Err(_err) = self.send_features().await {
                            break;
                        }
                    }
                }
                Ok(Some(XmlFrame::XmlFragment(fragment))) => {
                    dbg!(&fragment);
                    println!("{}", &fragment);
                }
                _ => break,
            }
        }
    }

    async fn send_stream_header(
        &mut self,
        from: &str,
        include_declaration: bool,
    ) -> Result<(), Error> {
        if include_declaration {
            self.connection.socket()
                .write_all("<?xml version='1.0'?>".as_bytes())
                .await?;
        }

        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        let mut id_raw = [0u8; 16];
        rng.fill_bytes(&mut id_raw);
        let id_encoded = base64::encode(id_raw);

        let stream_header = format!(
            r#"<stream:stream
    from="{}"
    id="{}"
    version="1.0"
    xml:lang="en"
    xmlns="jabber:client"
    xmlns:stream="http://etherx.jabber.org/streams">
"#,
            from, id_encoded
        );

        self.connection.socket().write_all(stream_header.as_bytes()).await?;
        Ok(())
    }

    async fn send_features(&mut self) -> Result<(), Error> {
        self.connection.socket().write_all("<stream:features>\n".as_bytes()).await?;
        self.sasl.advertise_feature(&mut self.connection, &self.settings).await?;
        self.connection.socket().write_all("</stream:features>\n".as_bytes()).await?;
        
        Ok(())
    }
}
