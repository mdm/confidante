use std::collections::HashSet;

use anyhow::Error;
use base64::prelude::*;
use rand::{RngCore, SeedableRng};
use tokio::io::{split, ReadHalf, WriteHalf};

use crate::{
    inbound::connection::{self, Connection},
    settings::get_settings,
    xml::{
        stream_parser::{rusty_xml::StreamParser as ConcreteStreamParser, StreamParser},
        stream_writer::StreamWriter,
    },
};

use self::{jid::Jid, stream_header::LanguageTag};

pub mod jid;
pub mod stanza;
pub mod stream_header;

#[derive(Debug, Clone)]
pub struct StreamId(String);

impl StreamId {
    pub fn new() -> Self {
        let id = Self::generate_id();
        Self(id)
    }

    fn generate_id() -> String {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy(); // TODO: use UUID instead?
        let mut id_raw = [0u8; 16];
        rng.fill_bytes(&mut id_raw);

        BASE64_STANDARD.encode(id_raw)
    }
}

enum ConnectionType {
    Client,
    Server,
}

enum StreamFeatures {
    Tls { with_authentication: bool },
    Authentication,
    ResourceBinding,
}

struct XmppStream<C>
where
    C: Connection,
{
    starttls_allowed: bool,
    reader: ConcreteStreamParser<ReadHalf<C>>,
    writer: StreamWriter<WriteHalf<C>>,
}

impl<C> XmppStream<C>
where
    C: Connection,
{
    pub fn new(connection: C) -> Self {
        let starttls_allowed = connection.is_starttls_allowed();
        let (reader, writer) = split(connection);
        let reader = ConcreteStreamParser::new(reader);
        let writer = StreamWriter::new(writer);

        Self {
            starttls_allowed,
            reader,
            writer,
        }
    }

    pub fn reset(mut self) -> XmppStream<C> {
        let reader = self.reader.into_inner();
        let writer = self.writer.into_inner();
        self.reader = ConcreteStreamParser::new(reader);
        self.writer = StreamWriter::new(writer);

        self
    }

    pub fn is_starttls_allowed(&self) -> bool {
        self.starttls_allowed
    }

    pub async fn upgrade_to_tls(mut self) -> Result<XmppStream<C>, Error> {
        let reader = self.reader.into_inner();
        let writer = self.writer.into_inner();
        let connection = reader.unsplit(writer);

        let connection = connection
            .upgrade(get_settings().tls.server_config.clone())?
            .await?;

        let (reader, writer) = split(connection);
        self.reader = ConcreteStreamParser::new(reader);
        self.writer = StreamWriter::new(writer);

        Ok(self)
    }
}

struct StreamInfo<C>
where
    C: Connection,
{
    stream_id: StreamId,
    jid: Jid,
    peer_jid: Option<Jid>,
    peer_language: LanguageTag,
    connection_type: ConnectionType,
    stream: XmppStream<C>,
}
