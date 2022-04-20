use bytes::BytesMut;
use rustyxml::{Element, ElementBuilder, Event, Parser};
use tokio_util::codec::Decoder;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum XmlFrame {
    OpenStream,
    XmlNode(Element),
    CloseStream,
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
                        Ok(Event::ElementStart(ref tag)) => {
                            if tag.name == "stream" {
                                self.element_builder = ElementBuilder::new();
                                return Ok(Some(XmlFrame::OpenStream));
                            }
                        }
                        Ok(Event::ElementEnd(ref tag)) => {
                            if tag.name == "stream" {
                                // TODO: reset parser & builder? discard data at least
                                return Ok(Some(XmlFrame::CloseStream));
                            }
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
                            Ok(element) => Ok(Some(XmlFrame::XmlNode(element))),
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
