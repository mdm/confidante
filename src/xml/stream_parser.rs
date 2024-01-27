use anyhow::Error;
use tokio::io::AsyncRead;
use tokio_stream::Stream;

use crate::xmpp::stream_header::StreamHeader;

use super::Element;

pub mod rusty_xml;

#[derive(Debug)]
pub enum Frame {
    StreamStart(StreamHeader),
    XmlFragment(Element),
    StreamEnd, // TODO: make implicit? (just return None instead of Some(StreamEnd)
               // TODO: Variant for character data (e.g. whitespace keep-alive)git d
}

pub trait StreamParser: Stream<Item = Result<Frame, Error>> + Unpin {
    type Reader: AsyncRead + Unpin;

    fn from_async_reader(reader: Self::Reader) -> Self;
    fn into_async_reader(self) -> Self::Reader;
}
