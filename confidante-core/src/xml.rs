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
    pub fn new(name: impl Into<String>, namespace: Option<impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.map(|s| s.into()),
            attributes: HashMap::new(),
            children: Vec::new(),
        }
    }

    pub fn validate(&self, name: impl AsRef<str>, namespace: Option<impl AsRef<str>>) -> bool {
        self.name == name.as_ref()
            && self.namespace.as_deref() == namespace.as_ref().map(|s| s.as_ref())
    }

    pub fn attribute(
        &self,
        name: impl AsRef<str>,
        namespace: Option<impl AsRef<str>>,
    ) -> Option<&str> {
        self.attributes.get(&(name, namespace)).map(|s| s.as_str())
    }

    pub fn set_attribute(
        &mut self,
        name: impl Into<String>,
        namespace: Option<impl Into<String>>,
        value: impl Into<String>,
    ) {
        self.attributes
            .insert((name.into(), namespace.map(|s| s.into())), value.into());
    }

    pub fn find_child(&self, name: &str, namespace: Option<&str>) -> Option<&Element> {
        self.children.iter().find_map(|child| match child {
            Node::Element(element) => {
                if element.name == name && element.namespace.as_deref() == namespace {
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

    pub fn with_child<F>(
        &mut self,
        name: impl Into<String>,
        namespace: Option<impl Into<String>>,
        f: F,
    ) where
        F: FnOnce(&mut Element),
    {
        let mut element = Element::new(name, namespace);
        f(&mut element);
        self.children.push(Node::Element(element));
    }

    pub fn add_text(&mut self, text: impl Into<String>) {
        self.children.push(Node::Text(text.into()));
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
        element.set_attribute("baz", None::<String>, "qux");
        assert_eq!(element.attribute("baz", None::<String>), Some("qux"));
    }

    #[test]
    fn attribute_missing() {
        let element = Element::new("foo", Some("bar"));
        assert_eq!(element.attribute("baz", None::<String>), None);
    }

    #[test]
    fn attribute_overwrite() {
        let mut element = Element::new("foo", Some("bar"));
        element.set_attribute("baz", None::<String>, "qux");
        element.set_attribute("baz", None::<String>, "overwritten");
        assert_eq!(
            element.attribute("baz", None::<String>),
            Some("overwritten")
        );
    }

    #[test]
    fn child_single() {
        let mut parent = Element::new("foo", Some("bar"));
        let child = Element::new("baz", Some("qux"));
        parent.add_child(child);
        assert!(parent.find_child("baz", Some("qux")).is_some());
        assert!(
            parent
                .find_child("baz", Some("qux"))
                .unwrap()
                .validate("baz", Some("qux"))
        );
    }

    #[test]
    fn child_multiple() {
        let mut parent = Element::new("foo", Some("bar"));
        let child = Element::new("baz", Some("baz"));
        parent.add_child(child);
        let child = Element::new("qux", Some("qux"));
        parent.add_child(child);
        assert!(parent.find_child("qux", Some("qux")).is_some());
        assert!(
            parent
                .find_child("qux", Some("qux"))
                .unwrap()
                .validate("qux", Some("qux"))
        );
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
            child.set_attribute("quux", None::<String>, "corge");
        });
        assert!(parent.find_child("baz", Some("qux")).is_some());
        assert_eq!(
            parent
                .find_child("baz", Some("qux"))
                .unwrap()
                .attribute("quux", None::<String>),
            Some("corge")
        );
    }

    #[test]
    fn text_simple() {
        let mut element = Element::new("foo", Some("bar"));
        element.add_text("baz");
        assert_eq!(element.text(), "baz");
    }

    #[test]
    fn text_nested() {
        let mut parent = Element::new("foo", Some("bar"));
        parent.add_text("before");
        parent.with_child("baz", Some("qux"), |child| {
            child.add_text("inside");
        });
        parent.add_text("after");
        assert_eq!(parent.text(), "beforeinsideafter");
    }
}
