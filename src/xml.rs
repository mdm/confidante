use std::collections::HashMap;

pub mod stream_parser;

#[derive(Debug)]
struct Element { // TODO: should we avoid udsing raw strings and replace with newtype?
    name: String,
    namespace: Option<String>,
    attributes: HashMap<String, String>,
    children: Vec<Element>,
}

struct XmlStream;

// impl Stream for XmlStream;

// impl Sink<Frame> for XmlStream;
