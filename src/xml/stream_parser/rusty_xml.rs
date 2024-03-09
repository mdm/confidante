use std::pin::Pin;
use std::task::{ready, Context, Poll};

use anyhow::{anyhow, Error};
use bytes::{Bytes, BytesMut};
use pin_project::pin_project;
use rustyxml::{Element as RustyXmlElement, ElementBuilder, Event, Parser};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::Stream;

use crate::xml::stream_parser::{Frame, StreamHeader};
use crate::xml::{Element, Node};
use crate::xmpp::stream_header::LanguageTag;

fn valid_stream_tag(name: &String, namespace: &Option<String>) -> bool {
    if name != "stream" {
        return false;
    }

    match namespace {
        Some(uri) => uri == "http://etherx.jabber.org/streams",
        None => false,
    }
}

impl From<RustyXmlElement> for Element {
    fn from(element: RustyXmlElement) -> Self {
        let name = element.name;
        let namespace = element.ns;
        let attributes = element.attributes;
        let children = element
            .children
            .into_iter()
            .map(|child| match child {
                rustyxml::Xml::ElementNode(element) => Node::Element(Element::from(element)),
                rustyxml::Xml::CharacterNode(text) => Node::Text(text),
                rustyxml::Xml::CDATANode(cdata) => Node::CData(cdata),
                rustyxml::Xml::CommentNode(comment) => Node::Comment(comment),
                rustyxml::Xml::PINode(pi) => Node::ProcessingInstruction(pi),
            })
            .collect();

        Element {
            name,
            namespace,
            attributes,
            children,
        }
    }
}

#[pin_project]
pub struct StreamParser<R: AsyncRead + Unpin> {
    #[pin]
    reader: R,
    buffer: Box<[u8]>,
    parser: Parser,
    element_builder: ElementBuilder,
}

impl<R: AsyncRead + Unpin> super::StreamParser for StreamParser<R> {
    type Reader = R;
    
    fn new(reader: R) -> Self {
        let buffer = vec![0; 4096].into_boxed_slice();
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

impl<R: AsyncRead + Unpin> Stream for StreamParser<R> {
    type Item = Result<Frame, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame, Error>>> {
        println!("polling parser");
        let mut this = self.project();
        while let Some(parser_result) = this.parser.next() {
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
                    return Poll::Ready(None);
                }
                Err(err) => {
                    // TODO: detect incomplete parses? or are those not even returned by the iterator?
                    dbg!("parser error");
                    return Poll::Ready(Some(Err(anyhow!(err))));
                }
                _ => {}
            }

            if let Some(builder_result) = this.element_builder.handle_event(parser_result) {
                let frame_result = match builder_result {
                    Ok(element) => Some(Ok(Frame::XmlFragment(element.into()))),
                    Err(err) => Some(Err(anyhow!(err))),
                };
                return Poll::Ready(frame_result);
            }
        }

        let mut buffer = ReadBuf::new(this.buffer);
        ready!(this.reader.poll_read(cx, &mut buffer))?;
        let bytes_read = buffer.filled().len();

        if bytes_read == 0 {
            return Poll::Ready(None);
        }

        match std::str::from_utf8(buffer.filled()) {
            Ok(str) => {
                println!("{}", str);
                this.parser.feed_str(str);
            }
            Err(err) => {
                dbg!("utf8 error");
                return Poll::Ready(Some(Err(anyhow!(err))));
            }
        }

        buffer.clear();

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
