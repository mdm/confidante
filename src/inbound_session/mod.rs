use futures::StreamExt;
use rand::{RngCore, SeedableRng};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::codec::{Decoder, Framed};

use crate::xml_stream_parser::{XmlFrame, XmlStreamParser};

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct InboundSession {
    socket: TcpStream,
    parser: XmlStreamParser,
}

impl InboundSession {
    pub fn from_socket(socket: TcpStream) -> Self {
        let parser = XmlStreamParser::new();

        Self { socket, parser }
    }

    pub async fn handle(&mut self) {
        loop {
            match self.parser.next_frame(&mut self.socket).await {
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
                Ok(Some(frame)) => {
                    dbg!(frame);
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
            self.socket
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

        self.socket.write_all(stream_header.as_bytes()).await?;
        Ok(())
    }

    async fn send_features(&mut self) -> Result<(), Error> {
        let features = r#"<stream:features>
    <mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
        <mechanism>SCRAM-SHA-1</mechanism>
        <mechanism>PLAIN</mechanism>
    </mechanisms>
</stream:features>
"#;

        self.socket.write_all(features.as_bytes()).await?;
        Ok(())
    }
}
