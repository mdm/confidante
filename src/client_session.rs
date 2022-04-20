use futures::StreamExt;
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Framed};

use crate::xml_stream_codec::XmlStreamCodec;

pub struct ClientSession {
    stream: Framed<TcpStream, XmlStreamCodec>,
}

impl ClientSession {
    pub fn from_socket(socket: TcpStream) -> Self {
        let codec = XmlStreamCodec::new();
        let stream = codec.framed(socket);

        Self {
            stream,
        }
    }

    pub async fn handle(&mut self) {
        loop {
            match self.stream.next().await {
                Some(frame) => {
                    dbg!(frame);
                }
                None => {
                    break;
                }
            }
        }
    }
}