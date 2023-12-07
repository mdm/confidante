use std::pin::Pin;
use std::task::{Poll, Context};

use anyhow::Error;
use tokio::io::AsyncRead;

use crate::jid::Jid;

use super::Element;

pub mod rusty_xml;

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
