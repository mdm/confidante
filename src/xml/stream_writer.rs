use std::collections::HashMap;

use anyhow::{anyhow, bail, Error};
use base64::prelude::*;
use rand::{RngCore, SeedableRng};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::xml::namespaces;
use crate::xml::Element;
use crate::xml::Node;
use crate::xmpp::stream_header::StreamHeader;

struct StreamWriter<'w, W: AsyncWrite + Unpin> {
    writer: &'w mut W,
    namespaces: Vec<HashMap<String, String>>, // stacked namespace to prefix map
}

impl<'w, W: AsyncWrite + Unpin> StreamWriter<'w, W> {
    pub fn new(writer: &mut W) -> Self {
        let mut namespaces = HashMap::new();
        namespaces.insert(namespaces::XML.to_string(), "xml".to_string());
        namespaces.insert(namespaces::XMLNS.to_string(), "xmlns".to_string());
        let namespaces = vec![namespaces];

        Self { writer, namespaces }
    }

    pub async fn write_stream_header(
        &mut self,
        header: &StreamHeader,
        include_xml_declaration: bool,
    ) -> Result<(), Error> {
        if include_xml_declaration {
            self.write_xml_declaration().await?;
        }

        let Some(ref from) = header.from else {
            bail!("`from` field is required in outgoing stream header");
        };

        let mut rng = rand_chacha::ChaCha20Rng::from_entropy(); // TODO: use UUID instead?
        let mut id_raw = [0u8; 16];
        rng.fill_bytes(&mut id_raw);
        let id_encoded = BASE64_STANDARD.encode(id_raw);

        let mut header_attributes = HashMap::new();
        header_attributes.insert(("from".to_string(), None), from.to_string());
        header_attributes.insert(("id".to_string(), None), id_encoded);
        header_attributes.insert(("version".to_string(), None), "1.0".to_string());
        header_attributes.insert(
            ("lang".to_string(), Some(namespaces::XML.to_string())),
            "en".to_string(),
        );
        header_attributes.insert(
            ("xmlns".to_string(), None),
            namespaces::XMPP_CLIENT.to_string(),
        );
        header_attributes.insert(
            ("stream".to_string(), Some(namespaces::XMLNS.to_string())),
            namespaces::XMPP_STREAMS.to_string(),
        );

        let header_element = Element {
            name: "stream".to_string(),
            namespace: Some(namespaces::XMPP_STREAMS.to_string()),
            attributes: header_attributes,
            children: vec![],
        };

        let formatted_header = self.build_opening_tag(&header_element, false);
        self.write_str(&formatted_header).await
    }

    pub async fn write_xml_element(&mut self, element: &Element) -> Result<(), Error> {
        self.write_str(&self.build_xml_element(element)).await
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.writer
            .write_all(bytes)
            .await
            .map_err(|err| anyhow!(err))
    }

    async fn write_str(&mut self, string: &str) -> Result<(), Error> {
        self.write_bytes(string.as_bytes()).await
    }

    async fn write_xml_declaration(&mut self) -> Result<(), Error> {
        self.write_str("<?xml version='1.0'?>").await
    }

    fn lookup_namespace_prefix(&self, namespace: &str) -> Option<&str> {
        for namespaces in self.namespaces.iter().rev() {
            if let Some(prefix) = namespaces.get(namespace) {
                return Some(prefix);
            }
        }

        None
    }

    fn build_xml_element(&self, element: &Element) -> String {
        let mut xml = String::new();

        if element.children.len() > 0 {
            self.build_opening_tag(element, false);
            self.build_children(element);
            self.build_closing_tag(element);
        } else {
            self.build_opening_tag(element, true);
        }

        xml
    }

    fn build_opening_tag(&mut self, element: &Element, self_closing: bool) -> String {
        let mut xml = String::new();

        // Iterate over attributes and process namespace declarations
        let mut namespaces = HashMap::new();
        for ((attribute, namespace), value) in element.attributes {
            match namespace {
                Some(namespace) => {
                    if namespace == namespaces::XMLNS {
                        namespaces.insert(value, attribute); // prefixed namespace
                    }
                }
                None => {
                    if attribute == "xmlns" {
                        namespaces.insert(value, String::new()); // default namespace
                    }
                }
            }
        }
        self.namespaces.push(namespaces);

        match element.namespace {
            Some(namespace) => match self.lookup_namespace_prefix(&namespace) {
                Some("") => {
                    // Element is in the default namespace
                    xml.push_str(&format!(
                        "<{}{}",
                        element.name,
                        self.build_attributes(&element)
                    ));
                }
                Some(prefix) => {
                    // Element is in a prefixed namespace
                    xml.push_str(&format!(
                        "<{}:{}{}",
                        prefix,
                        element.name,
                        self.build_attributes(&element)
                    ));
                }
                None => {
                    debug_assert!(false, "namespace not declared");
                    // TODO: declare namespace with generated prefix and write anyways
                }
            },
            None => {
                xml.push_str(&format!(
                    "<{}{}",
                    element.name,
                    self.build_attributes(&element)
                ));
            }
        }

        if self_closing {
            self.namespaces.pop();

            xml.push_str("/>");
        } else {
            xml.push_str(">");
        }

        xml
    }

    fn build_attributes(&self, element: &Element) -> String {
        let mut xml = String::new();

        for ((attribute, namespace), value) in element.attributes {
            match namespace {
                Some(namespace) => match self.lookup_namespace_prefix(&namespace) {
                    Some("") => {
                        debug_assert!(false, "cannot use default namespace for attribute");
                        // TODO: declare namespace with generated prefix and write anyways
                    }
                    Some(prefix) => {
                        xml.push_str(&format!(r#" {}:{}="{}""#, prefix, attribute, value,));
                    }
                    None => {
                        debug_assert!(false, "namespace not declared");
                        // TODO: declare namespace with generated prefix and write anyways
                    }
                },
                None => {
                    xml.push_str(&format!(r#" {}="{}""#, attribute, value,));
                }
            }
        }

        xml
    }

    fn build_children(&mut self, element: &Element) -> String {
        let mut xml = String::new();

        for child in &element.children {
            match child {
                Node::Element(child_element) => {
                    xml.push_str(&self.build_xml_element(child_element));
                }
                Node::Text(text) => {
                    xml.push_str(text);
                }
                Node::CData(cdata) => {
                    xml.push_str(&format!("<![CDATA[{}]]>", cdata));
                }
                Node::Comment(comment) => {
                    xml.push_str(&format!("<!--{}-->", comment));
                }
                Node::ProcessingInstruction(pi) => {
                    xml.push_str(&format!("<?{}?>", pi));
                }
            }
        }

        xml
    }

    fn build_closing_tag(&mut self, element: &Element) -> String {
        self.namespaces.pop();

        format!("</{}>", element.name)
    }
}
