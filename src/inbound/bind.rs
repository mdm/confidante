use std::{collections::HashMap, vec};

use anyhow::{bail, Error};
use tokio::io::AsyncWrite;
use tokio_stream::StreamExt;

use crate::{
    xml::{
        namespaces,
        stream_parser::{Frame, StreamParser},
        stream_writer::StreamWriter,
        Element, Node,
    },
    xmpp::jid::Jid,
};

use super::sasl::AuthenticatedEntity;

#[derive(Debug)]
pub struct BoundResource(pub String, ());

pub struct ResourceBindingNegotiator {
    _private: (),
}

impl ResourceBindingNegotiator {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn advertise_feature(&self) -> Element {
        // TODO: decide if this should be part of a trait
        let mut attributes = HashMap::new();
        attributes.insert(
            ("xmlns".to_string(), None),
            namespaces::XMPP_BIND.to_string(),
        );

        Element {
            name: "bind".to_string(),
            namespace: Some("urn:ietf:params:xml:ns:xmpp-bind".to_string()),
            attributes,
            children: vec![],
        }
    }

    pub async fn bind_resource<P: StreamParser, W: AsyncWrite + Unpin>(
        &self,
        stream_parser: &mut P,
        stream_writer: &mut StreamWriter<W>,
        entity: &Jid,
    ) -> Result<Jid, Error> {
        let Some(Ok(Frame::XmlFragment(iq_stanza))) = stream_parser.next().await else {
            bail!("expected xml fragment");
        };
        dbg!(&iq_stanza);

        if iq_stanza.name != "iq" {
            // TODO: check namespace
            bail!("expected IQ stanza");
        }

        if iq_stanza.get_attribute("type", None) != Some("set") {
            bail!("IQ stanza is not of type set");
        };

        let Some(request_id) = iq_stanza.get_attribute("id", None) else {
            bail!("IQ stanza does not have an id");
        };

        let Some(bind_request) = iq_stanza.get_child("bind", Some(namespaces::XMPP_BIND)) else {
            bail!("IQ stanza does not contain a bind request");
        };

        let resource = match bind_request.get_child("resource", Some(namespaces::XMPP_BIND)) {
            Some(requested_resource) => requested_resource.get_text(),
            None => uuid::Uuid::new_v4().to_string(),
        };

        // TODO: check resource availability and maximum number of connected resources

        let bound_entity = entity.bind(resource);

        let bind_response = Element {
            name: "iq".to_string(),
            namespace: None,
            attributes: vec![
                (("id".to_string(), None), request_id.to_string()),
                (("type".to_string(), None), "result".to_string()),
            ]
            .into_iter()
            .collect(),
            children: vec![Node::Element(Element {
                name: "bind".to_string(),
                namespace: Some(namespaces::XMPP_BIND.to_string()),
                attributes: vec![(
                    ("xmlns".to_string(), None),
                    namespaces::XMPP_BIND.to_string(),
                )]
                .into_iter()
                .collect(),
                children: vec![Node::Element(Element {
                    name: "jid".to_string(),
                    namespace: None,
                    attributes: HashMap::new(),
                    children: vec![Node::Text(format!("{}", bound_entity))],
                })],
            })],
        };

        stream_writer.write_xml_element(&bind_response).await?;

        Ok(bound_entity)
    }
}
