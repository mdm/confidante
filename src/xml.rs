use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
};

pub mod stream_parser;
pub mod stream_writer;

#[derive(Debug)]
pub struct Element {
    // TODO: should we avoid udsing raw strings and replace with newtype?
    name: String,
    namespace: Option<String>,
    attributes: HashMap<String, String>,
    children: Vec<Element>,
}

impl Display for Element {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.namespace {
            Some(namespace) => write!(f, "<{}:{}", namespace, self.name)?,
            None => write!(f, "<{}", self.name)?,
        }

        for (key, value) in &self.attributes {
            write!(f, r#" {}="{}""#, key, value)?;
        }

        if self.children.len() > 0 {
            write!(f, ">")?;

            for child in &self.children {
                write!(f, "{}", child)?;
            }

            match &self.namespace {
                Some(namespace) => write!(f, "</{}:{}>", namespace, self.name)?,
                None => write!(f, "</{}>", self.name)?,
            }
        } else {
            write!(f, "/>")?;
        }

        Ok(())
    }
}
