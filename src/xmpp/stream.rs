use std::future::Future;
use std::sync::Arc;

use anyhow::Error;
use base64::prelude::*;
use rand::{RngCore, SeedableRng};
use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_rustls::rustls::ServerConfig;

use crate::{
    settings::get_settings,
    xml::{stream_parser::StreamParser, stream_writer::StreamWriter},
};

#[derive(Debug, Clone)]
pub struct StreamId(String);

impl StreamId {
    pub fn new() -> Self {
        let id = Self::generate_id();
        Self(id)
    }

    fn generate_id() -> String {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        let mut id_raw = [0u8; 16];
        rng.fill_bytes(&mut id_raw);

        BASE64_STANDARD.encode(id_raw)
    }
}

pub trait Connection: AsyncRead + AsyncWrite + Unpin + Sized {
    type Upgrade: Future<Output = Result<Self, Error>> + Send + 'static;

    fn upgrade(self, config: Arc<ServerConfig>) -> Result<Self::Upgrade, Error>;
    fn is_starttls_allowed(&self) -> bool;
    fn is_secure(&self) -> bool;
    fn is_authenticated(&self) -> bool;
}

pub struct XmppStream<C, P>
where
    C: Connection,
    P: StreamParser<ReadHalf<C>>,
{
    starttls_allowed: bool,
    secure: bool,
    authenticated: bool,
    reader: Option<P>,
    writer: Option<StreamWriter<WriteHalf<C>>>,
}

impl<C, P> XmppStream<C, P>
where
    C: Connection,
    P: StreamParser<ReadHalf<C>>,
{
    pub fn new(connection: C) -> Self {
        let starttls_allowed = connection.is_starttls_allowed();
        let secure = connection.is_secure();
        let authenticated = connection.is_authenticated();
        let (reader, writer) = split(connection);
        let reader = Some(P::new(reader));
        let writer = Some(StreamWriter::new(writer));

        Self {
            starttls_allowed,
            secure,
            authenticated,
            reader,
            writer,
        }
    }

    pub fn reset(&mut self) {
        let reader = self.reader.take().unwrap().into_inner();
        let writer = self.writer.take().unwrap().into_inner();
        self.reader = Some(P::new(reader));
        self.writer = Some(StreamWriter::new(writer));
    }

    pub fn is_starttls_allowed(&self) -> bool {
        self.starttls_allowed
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn reader(&mut self) -> &mut P {
        self.reader.as_mut().unwrap()
    }

    pub fn writer(&mut self) -> &mut StreamWriter<WriteHalf<C>> {
        self.writer.as_mut().unwrap()
    }

    pub async fn upgrade_to_tls(&mut self) -> Result<(), Error> {
        let reader = self.reader.take().unwrap().into_inner();
        let writer = self.writer.take().unwrap().into_inner();
        let connection = reader.unsplit(writer);

        let connection = connection
            .upgrade(get_settings().tls.server_config.clone())?
            .await?;

        self.starttls_allowed = connection.is_starttls_allowed();
        self.secure = connection.is_secure();
        self.authenticated = connection.is_authenticated();

        let (reader, writer) = split(connection);
        self.reader = Some(P::new(reader));
        self.writer = Some(StreamWriter::new(writer));

        Ok(())
    }
}
