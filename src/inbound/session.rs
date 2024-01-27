use anyhow::{anyhow, Error};
use base64::prelude::*;
use bytes::Buf;
use rand::{RngCore, SeedableRng};
use tokio::net::tcp::{WriteHalf, ReadHalf};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_stream::StreamExt;

use crate::jid::Jid;
use crate::settings::Settings;
use crate::xml::stream_parser::{
    rusty_xml::StreamParser as ConcreteStreamParser, Frame, StreamParser,
};

use super::tls::TlsToken;


// TODO: merge with InboundSession and eliminate this struct
pub struct Session<'s> {
    pub settings: Settings,
    pub writer: WriteHalf<'s>, // TODO: Refactor to make this private again
    reader: ConcreteStreamParser<'s, ReadHalf<'s>>,
}

impl<'s> Session<'s> {
    pub fn from_socket(mut socket: TcpStream, settings: Settings) -> Self {
        let (reader, writer) = socket.split();
        let reader = ConcreteStreamParser::from_async_reader(reader);

        Self {
            writer,
            reader,
            settings,
        }
    }

    pub async fn receive_stream_header(&mut self) -> Result<Jid, Error> {
        match self.read_frame().await {
            Ok(Some(Frame::StreamStart(stream_header))) => {
                // TODO: check "stream" namespace here or in parser?

                match stream_header.to {
                    Some(to) => Ok(to),
                    None => Err(anyhow!()),
                }
            }
            _ => Err(anyhow!("could not read stream header")),
        }
    }


    pub async fn read_frame(&mut self) -> Result<Option<Frame>, Error> {
        // TODO: refactor to get rid of transpose
        self.reader.next().await.transpose()
    }


    pub async fn write_buffer(&mut self, buffer: &mut impl Buf) -> Result<(), Error> {
        self.writer
            .write_all_buf(buffer)
            .await
            .map_err(|err| anyhow!(err))
    }

    pub fn set_secure(&mut self, token: TlsToken) {
        todo!()
    }
}
