use anyhow::{anyhow, Error};
use bytes::BytesMut;
use rustyxml::{Element, ElementBuilder, Event, Parser, StartTag};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

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

pub struct XmlStreamParser {
    parser: Parser,
    element_builder: ElementBuilder,
}

impl XmlStreamParser {
    pub fn new() -> Self {
        let parser = Parser::new();
        let element_builder = ElementBuilder::new();

        Self {
            parser,
            element_builder,
        }
    }

    pub async fn next_frame(&mut self, socket: &mut TcpStream) -> Result<Option<XmlFrame>, Error> {
        let mut buffer = BytesMut::with_capacity(4096);

        loop {
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
                        return Err(anyhow!(err));
                    }
                    _ => {}
                }

                if let Some(builder_result) = self.element_builder.handle_event(parser_result) {
                    return match builder_result {
                        Ok(element) => Ok(Some(XmlFrame::XmlFragment(element))),
                        Err(err) => Err(anyhow!(err)),
                    }
                }
            }

            let bytes_read = socket.read_buf(&mut buffer).await?;

            if bytes_read == 0 {
                return Ok(None);
            }

            match std::str::from_utf8(&buffer.split_to(bytes_read)) {
                Ok(str) => {
                    self.parser.feed_str(str);
                }
                Err(err) => {
                    dbg!("utf8 error");
                    return Err(anyhow!(err));
                }
            }
        }
    }
}
