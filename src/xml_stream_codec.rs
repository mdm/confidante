use bytes::BytesMut;
use rustyxml::{Element, ElementBuilder, Event, Parser, StartTag};
use tokio_util::codec::Decoder;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum XmlFrame {
    StreamStart(StartTag),
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

pub struct XmlStreamCodec {
    parser: Parser,
    element_builder: ElementBuilder,
}

impl XmlStreamCodec {
    pub fn new() -> Self {
        let parser = Parser::new();
        let element_builder = ElementBuilder::new();

        Self {
            parser,
            element_builder,
        }
    }
}

impl Decoder for XmlStreamCodec {
    type Item = XmlFrame;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        dbg!(&src);
        match std::str::from_utf8(&src.split_to(src.len())) {
            Ok(str) => {
                self.parser.feed_str(str);
                // TODO: don't use for loop here - does it matter? (we return in both match arms)
                for parser_result in &mut self.parser {
                    match parser_result {
                        Ok(Event::ElementStart(tag)) if valid_stream_tag(&tag.name, &tag.ns) => {
                            dbg!(&tag.ns);
                            return Ok(Some(XmlFrame::StreamStart(tag)));
                        }
                        Ok(Event::ElementEnd(tag)) if valid_stream_tag(&tag.name, &tag.ns) => {
                            // TODO: reset parser & builder? discard data at least
                            return Ok(Some(XmlFrame::StreamEnd));
                        }
                        Err(err) => {
                            // TODO: detect incomplete parses? or are those not even returned by the iterator?
                            dbg!("parser error");
                            return Err(Box::new(err));
                        }
                        _ => {}
                    }

                    if let Some(builder_result) = self.element_builder.handle_event(parser_result) {
                        return match builder_result {
                            Ok(element) => Ok(Some(XmlFrame::XmlFragment(element))),
                            Err(err) => Err(Box::new(err)),
                        }
                    }
                }
            }
            Err(err) => {
                dbg!("utf8 error");
                return Err(Box::new(err));
            }
        }

        dbg!("incomplete 2");
        Ok(None)
    }
}
