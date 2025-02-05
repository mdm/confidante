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
}

pub trait StreamParser<R: AsyncRead + Unpin>: Stream<Item = Result<Frame, Error>> + Unpin {
    fn new(reader: R) -> Self;
    fn into_inner(self) -> R;
}
