use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{anyhow, Error};
use bytes::BytesMut;
use rustyxml::{Element, ElementBuilder, Event, Parser, StartTag};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::xml::{Frame, StreamParser, StreamHeader, LanguageTag};

#[derive(Debug)]
pub enum XmlFrame {
    StreamStart(StartTag), // TODO: parse stream start into struct also usable for output
    XmlFragment(Element),
    StreamEnd,
    // TODO: Variant for character data (e.g. whitespace keep-alive)
}

fn valid_stream_tag(name: &String, namespace: &Option<String>) -> bool {
    if name != "stream" {
        return false;
    }
        
    return match namespace {
        Some(uri) => uri == "http://etherx.jabber.org/streams",
        None => false,
    }
}

pub struct RustyXmlStreamParser<R: AsyncRead + Unpin> {
    reader: R,
    parser: Parser,
    element_builder: ElementBuilder,
}

impl<R: AsyncRead + Unpin> StreamParser<R> for RustyXmlStreamParser<R> {
    fn from_async_reader(reader: R) -> Self {
        let parser = Parser::new();
        let element_builder = ElementBuilder::new();

        Self {
            reader,
            parser,
            element_builder,
        }
    }

    fn poll_next_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Option<Frame>, Error>> {
        let mut buffer = BytesMut::with_capacity(4096); // TODO: don't allocate for each poll

        loop {
            // TODO: don't use for loop here - does it matter? (we return in both match arms)
            for parser_result in &mut self.parser {
                match parser_result {
                    Ok(Event::ElementStart(tag)) if valid_stream_tag(&tag.name, &tag.ns) => {
                        dbg!(&tag.ns, &tag.attributes);
                        let header = StreamHeader {
                            from: tag.attributes.get(&("from".to_string(), None)).and_then(|jid| jid.parse().ok()),
                            to: tag.attributes.get(&("to".to_string(), None)).and_then(|jid| jid.parse().ok()),
                            id: None,
                            language: tag.attributes.get(&("xml:lang".to_string(), None)).map(|lang| LanguageTag(lang.to_string())),
                        };
                        return Poll::Ready(Ok(Some(Frame::StreamStart(header))));
                    }
                    Ok(Event::ElementEnd(tag)) if valid_stream_tag(&tag.name, &tag.ns) => {
                        // TODO: reset parser & builder? discard data at least
                        return Poll::Ready(Ok(Some(Frame::StreamEnd)));
                    }
                    Err(err) => {
                        // TODO: detect incomplete parses? or are those not even returned by the iterator?
                        dbg!("parser error");
                        return Poll::Ready(Err(anyhow!(err)));
                    }
                    _ => {}
                }

                if let Some(builder_result) = self.element_builder.handle_event(parser_result) {
                    return Poll::Ready(match builder_result {
                        Ok(element) => Ok(Some(Frame::XmlFragment(element))),
                        Err(err) => Err(anyhow!(err)),
                    })
                }
            }

            let bytes_read = socket.read_buf(&mut buffer);

            if bytes_read == 0 {
                return Poll::Ready(Ok(None));
            }

            match std::str::from_utf8(&buffer.split_to(bytes_read)) {
                Ok(str) => {
                    println!("{}", str);
                    self.parser.feed_str(str);
                }
                Err(err) => {
                    dbg!("utf8 error");
                    return Poll::Ready(Err(anyhow!(err)));
                }
            }
        }
    }

    fn into_async_reader(self) -> R {
        self.reader
    }
}
