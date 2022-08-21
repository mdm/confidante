use anyhow::{anyhow, Error};
use bytes::Buf;
use rand::{RngCore, SeedableRng};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::settings::Settings;
use crate::xml_stream_parser::{XmlFrame, XmlStreamParser};

use super::connection::Connection;
use super::tls::TlsToken;

pub struct Session {
    pub settings: Settings,
    pub connection: Connection, // TODO: Refactor to make this private again
    parser: XmlStreamParser,
}

impl Session {
    pub fn from_socket(socket: TcpStream, settings: Settings) -> Self {
        let connection = Connection::from_socket(socket);
        let parser = XmlStreamParser::new();

        Self { connection, parser, settings }
    }
    
    pub async fn receive_stream_header(&mut self) -> Result<String, Error> {
        match self.read_frame().await {
            Ok(Some(XmlFrame::StreamStart(stream_header))) => {
                match stream_header.attributes.get(&("xmlns".into(), None)) {
                    Some(xmlns) => match xmlns.as_str() {
                        "jabber:client" => {
                            self.connection.set_client_connection();
                        }
                        _ => todo!(),
                    }
                    _ => todo!(),
                }
                
                match stream_header.attributes.get(&("to".into(), None)) {
                    Some(to) => Ok(to.into()),
                    None => Err(anyhow!("expected `to` attribute on stream header")),
                }
            }
            _ => Err(anyhow!("could not read stream header"))
        }
    }

    pub async fn send_stream_header(
        &mut self,
        from: &str,
        include_declaration: bool,
    ) -> Result<(), Error> {
        if include_declaration {
            self.write_bytes("<?xml version='1.0'?>".as_bytes()).await?;
        }

        let mut rng = rand_chacha::ChaCha20Rng::from_entropy(); // TODO: use UUID instead?
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

        self.write_bytes(stream_header.as_bytes()).await?;
        Ok(())
    }

    pub async fn read_frame(&mut self) -> Result<Option<XmlFrame>, Error> {
        self.parser.next_frame(&mut self.connection.socket()).await
    }

    pub async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.connection.socket().write_all(bytes).await.map_err(|err| anyhow!(err))
    }

    pub async fn write_buffer(&mut self, buffer: &mut impl Buf) -> Result<(), Error> {
        self.connection.socket().write_all_buf(buffer).await.map_err(|err| anyhow!(err))
    }

    pub fn set_secure(&mut self, token: TlsToken) {
        todo!()
    }
}
