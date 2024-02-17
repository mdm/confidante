use std::pin::Pin;
use std::task::{ready, Context, Poll};

use anyhow::{anyhow, Error};
use bytes::BytesMut;
use rustyxml::{Element as RustyXmlElement, ElementBuilder, Event, Parser};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::Stream;

use crate::xml::stream_parser::{Frame, StreamHeader};
use crate::xml::Element;
use crate::xmpp::stream_header::LanguageTag;

fn valid_stream_tag(name: &String, namespace: &Option<String>) -> bool {
    if name != "stream" {
        return false;
    }

    return match namespace {
        Some(uri) => uri == "http://etherx.jabber.org/streams",
        None => false,
    };
}

impl From<RustyXmlElement> for Element {
    fn from(element: RustyXmlElement) -> Self {
        let name;
        let namespace;
        let attributes;
        let children;

        Element {
            name,
            namespace,
            attributes,
            children,
        }
    }
}

pub struct StreamParser<'a, R: AsyncRead + Unpin> {
    reader: R,
    buffer: ReadBuf<'a>,
    parser: Parser,
    element_builder: ElementBuilder,
}

impl<'a, R: AsyncRead + Unpin> super::StreamParser for StreamParser<'a, R> {
    type Reader = R;
    
    fn new(reader: R) -> Self {
        let buffer = ReadBuf::new(&mut BytesMut::with_capacity(4096));
        let parser = Parser::new();
        let element_builder = ElementBuilder::new();

        Self {
            reader,
            buffer,
            parser,
            element_builder,
        }
    }

    fn into_inner(self) -> R {
        self.reader
    }
}

impl<'a, R: AsyncRead + Unpin> Stream for StreamParser<'a, R> {
    type Item = Result<Frame, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame, Error>>> {
        loop {
            // TODO: don't use for loop here - does it matter? (we return in both match arms)
            for parser_result in &mut self.parser {
                match parser_result {
                    Ok(Event::ElementStart(tag)) if valid_stream_tag(&tag.name, &tag.ns) => {
                        dbg!(&tag.ns, &tag.attributes);
                        let header = StreamHeader {
                            from: tag
                                .attributes
                                .get(&("from".to_string(), None))
                                .and_then(|jid| jid.parse().ok()),
                            to: tag
                                .attributes
                                .get(&("to".to_string(), None))
                                .and_then(|jid| jid.parse().ok()),
                            id: None,
                            language: tag
                                .attributes
                                .get(&("xml:lang".to_string(), None))
                                .map(|lang| LanguageTag(lang.to_string())),
                        };
                        return Poll::Ready(Some(Ok(Frame::StreamStart(header))));
                    }
                    Ok(Event::ElementEnd(tag)) if valid_stream_tag(&tag.name, &tag.ns) => {
                        // TODO: reset parser & builder? discard data at least
                        return Poll::Ready(Some(Ok(Frame::StreamEnd)));
                    }
                    Err(err) => {
                        // TODO: detect incomplete parses? or are those not even returned by the iterator?
                        dbg!("parser error");
                        return Poll::Ready(Some(Err(anyhow!(err))));
                    }
                    _ => {}
                }

                if let Some(builder_result) = self.element_builder.handle_event(parser_result) {
                    let frame_result = match builder_result {
                        Ok(element) => Some(Ok(Frame::XmlFragment(element.into()))),
                        Err(err) => Some(Err(anyhow!(err))),
                    };
                    return Poll::Ready(frame_result);
                }
            }

            ready!(Pin::new(&mut self.reader).poll_read(cx, &mut self.buffer))?;
            let bytes_read = self.buffer.filled().len();

            if bytes_read == 0 {
                return Poll::Ready(None);
            }

            match std::str::from_utf8(&self.buffer.filled()) {
                Ok(str) => {
                    println!("{}", str);
                    self.parser.feed_str(str);
                }
                Err(err) => {
                    dbg!("utf8 error");
                    return Poll::Ready(Some(Err(anyhow!(err))));
                }
            }

            self.buffer.clear();
        }
    }
}
