use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Poll, Context};

use anyhow::Error;
use tokio::io::AsyncRead;

use crate::jid::Jid;

pub mod rusty_xml_stream_parser;

#[derive(Debug)]
struct StreamId(String);

#[derive(Debug)]
struct LanguageTag(String);

#[derive(Debug)]
struct StreamHeader {
    from: Option<Jid>,
    to: Option<Jid>,
    id: Option<StreamId>,
    language: Option<LanguageTag>,
}

#[derive(Debug)]
struct Element { // TODO: should we avoid udsing raw strings and replace with newtype?
    name: String,
    namespace: Option<String>,
    attributes: HashMap<String, String>,
    children: Vec<Element>,
}

#[derive(Debug)]
pub enum Frame {
    StreamStart(StreamHeader),
    XmlFragment(Element),
    StreamEnd,
    // TODO: Variant for character data (e.g. whitespace keep-alive)
}

trait StreamParser<R: AsyncRead + Unpin> { 
    fn from_async_reader(reader: R) -> Self;
    fn poll_next_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Option<Frame>, Error>>;
    fn into_async_reader(self) -> R;
}

struct XmlStream;

// impl Stream for XmlStream;

// impl Sink<Frame> for XmlStream;
