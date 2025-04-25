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

    pub fn find_child(&self, name: &str, namespace: Option<&str>) -> Option<&Element> {
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

    pub fn add_child(&mut self, element: Element) {
        self.children.push(Node::Element(element));
    }

    pub fn with_child<F>(&mut self, name: &str, namespace: Option<&str>, f: F)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_simple() {
        let element = Element::new("foo", Some("bar"));
        assert!(element.validate("foo", Some("bar")));
    }

    #[test]
    fn validate_different_name() {
        let element = Element::new("foo", Some("bar"));
        assert!(!element.validate("baz", Some("bar")));
    }

    #[test]
    fn validate_different_namespace() {
        let element = Element::new("foo", Some("bar"));
        assert!(!element.validate("foo", Some("baz")));
    }

    #[test]
    fn attribute_simple() {
        let mut element = Element::new("foo", Some("bar"));
        element.set_attribute("baz", None, "qux".to_string());
        assert_eq!(element.attribute("baz", None), Some("qux"));
    }

    #[test]
    fn attribute_missing() {
        let element = Element::new("foo", Some("bar"));
        assert_eq!(element.attribute("baz", None), None);
    }

    #[test]
    fn attribute_overwrite() {
        let mut element = Element::new("foo", Some("bar"));
        element.set_attribute("baz", None, "qux".to_string());
        element.set_attribute("baz", None, "overwritten".to_string());
        assert_eq!(element.attribute("baz", None), Some("overwritten"));
    }

    #[test]
    fn child_single() {
        let mut parent = Element::new("foo", Some("bar"));
        let child = Element::new("baz", Some("qux"));
        parent.add_child(child);
        assert!(parent.find_child("baz", Some("qux")).is_some());
        assert!(parent
            .find_child("baz", Some("qux"))
            .unwrap()
            .validate("baz", Some("qux")));
    }

    #[test]
    fn child_multiple() {
        let mut parent = Element::new("foo", Some("bar"));
        let child = Element::new("baz", Some("baz"));
        parent.add_child(child);
        let child = Element::new("qux", Some("qux"));
        parent.add_child(child);
        assert!(parent.find_child("qux", Some("qux")).is_some());
        assert!(parent
            .find_child("qux", Some("qux"))
            .unwrap()
            .validate("qux", Some("qux")));
    }

    #[test]
    fn child_missing() {
        let parent = Element::new("foo", Some("bar"));
        assert!(parent.find_child("baz", Some("qux")).is_none());
    }

    #[test]
    fn child_helper() {
        let mut parent = Element::new("foo", Some("bar"));
        parent.with_child("baz", Some("qux"), |child| {
            child.set_attribute("quux", None, "corge".to_string());
        });
        assert!(parent.find_child("baz", Some("qux")).is_some());
        assert_eq!(
            parent
                .find_child("baz", Some("qux"))
                .unwrap()
                .attribute("quux", None),
            Some("corge")
        );
    }

    #[test]
    fn text_simple() {
        let mut element = Element::new("foo", Some("bar"));
        element.add_text("baz".to_string());
        assert_eq!(element.text(), "baz");
    }

    fn text_nested() {
        let mut parent = Element::new("foo", Some("bar"));
        parent.add_text("before".to_string());
        parent.with_child("baz", Some("qux"), |child| {
            child.add_text("inside".to_string());
        });
        parent.add_text("after".to_string());
        assert_eq!(parent.text(), "beforeinsideafter");
    }
}
