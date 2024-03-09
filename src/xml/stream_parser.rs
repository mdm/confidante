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
    // TODO: Variant for character data (e.g. whitespace keep-alive)
}

pub trait StreamParser: Stream<Item = Result<Frame, Error>> + Unpin {
    type Reader: AsyncRead + Unpin;

    fn new(reader: Self::Reader) -> Self;
    fn into_inner(self) -> Self::Reader;
}
