use std::collections::HashMap;

pub mod namespaces;
pub mod stream_parser;
pub mod stream_writer;

#[derive(Debug)]
enum Node {
    Element(Element),
    Text(String),
    CData(String),
    Comment(String),
    ProcessingInstruction(String),
}

#[derive(Debug)]
pub struct Element {
    name: String,
    namespace: Option<String>,
    attributes: HashMap<(String, Option<String>), String>,
    children: Vec<Node>,
}

impl Element {
    pub fn new(name: &str, namespace: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.map(|s| s.to_string()),
            attributes: HashMap::new(),
            children: Vec::new(),
        }
    }

    pub fn validate(&self, name: &str, namespace: Option<&str>) -> bool {
        self.name == name && self.namespace == namespace.map(|s| s.to_string())
    }

    pub fn attribute(&self, name: &str, namespace: Option<&str>) -> Option<&str> {
        self.attributes
            .get(&(name.to_string(), namespace.map(|s| s.to_string())))
            .map(|s| s.as_str())
    }

    pub fn set_attribute(&mut self, name: &str, namespace: Option<&str>, value: String) {
        self.attributes.insert(
            (name.to_string(), namespace.map(|s| s.to_string())),
            value.to_string(),
        );
    }

    pub fn child(&self, name: &str, namespace: Option<&str>) -> Option<&Element> {
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

    pub fn text(&self) -> String {
        let mut text = String::new();
        for child in &self.children {
            match child {
                Node::Element(element) => text.push_str(&element.text()),
                Node::Text(s) => text.push_str(s),
                Node::CData(s) => text.push_str(s),
                _ => {}
            }
        }
        text
    }

    pub fn add_element(&mut self, element: Element) {
        self.children.push(Node::Element(element));
    }

    pub fn with_element<F>(&mut self, name: &str, namespace: Option<&str>, f: F)
    where
        F: FnOnce(&mut Element),
    {
        let mut element = Element::new(name, namespace);
        f(&mut element);
        self.children.push(Node::Element(element));
    }

    pub fn add_text(&mut self, text: String) {
        self.children.push(Node::Text(text));
    }

    pub fn add_cdata(&mut self, cdata: String) {
        self.children.push(Node::CData(cdata));
    }

    pub fn add_comment(&mut self, comment: String) {
        self.children.push(Node::Comment(comment));
    }

    pub fn add_processing_instruction(&mut self, processing_instruction: String) {
        self.children
            .push(Node::ProcessingInstruction(processing_instruction));
    }
}
