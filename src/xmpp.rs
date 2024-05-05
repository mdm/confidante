use std::collections::HashSet;

use base64::prelude::*;
use rand::{RngCore, SeedableRng};
use tokio::io::{ReadHalf, WriteHalf};

use crate::{
    inbound::connection::Connection,
    xml::{
        stream_parser::rusty_xml::StreamParser as ConcreteStreamParser, stream_writer::StreamWriter,
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
    stream_id: StreamId,
    jid: Jid,
    peer_jid: Option<Jid>,
    peer_language: LanguageTag,
    connection_type: ConnectionType,
    negotiated_features: HashSet<StreamFeatures>,
    parser: ConcreteStreamParser<ReadHalf<C>>,
    writer: StreamWriter<WriteHalf<C>>,
}
