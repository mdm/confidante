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

impl Element {
    pub fn get_attribute(&self, name: &str, namespace: Option<&str>) -> Option<&str> {
        self.attributes
            .get(&(name.to_string(), namespace.map(|s| s.to_string())))
            .map(|s| s.as_str())
    }

    pub fn get_child(&self, name: &str, namespace: Option<&str>) -> Option<&Element> {
        self.children.iter().find_map(|child| match child {
            Node::Element(element) => {
                if element.name == name && element.namespace == namespace.map(|s| s.to_string()) {
                    Some(element)
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    pub fn get_text(&self) -> String {
        let mut text = String::new();
        for child in &self.children {
            match child {
                Node::Element(element) => text.push_str(&element.get_text()),
                Node::Text(s) => text.push_str(s),
                Node::CData(s) => text.push_str(s), // TODO: is this correct?
                _ => {}
            }
        }
        text
    }
}
