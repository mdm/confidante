use std::collections::HashMap;

pub mod namespaces;
pub mod stream_parser;
pub mod stream_writer;

#[derive(Debug)]
pub enum Node {
    Element(Element),
    Text(String),
    CData(String),
    Comment(String),
    ProcessingInstruction(String),
}

#[derive(Debug)]
pub struct Element {
    // TODO: should we avoid udsing raw strings and replace with newtype?
    pub name: String,
    pub namespace: Option<String>,
    pub attributes: HashMap<(String, Option<String>), String>,
    pub children: Vec<Node>,
}
