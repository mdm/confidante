use std::{collections::HashMap, vec};

use anyhow::{bail, Error};

use crate::{
    xml::{namespaces, Element, Node},
    xmpp::{
        jid::Jid,
        stream::{Connection, XmppStream},
    },
};

#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct BoundResource(pub String, ());

pub struct ResourceBindingNegotiator {
    _private: (),
}

impl ResourceBindingNegotiator {
    pub fn advertise_feature() -> Element {
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

    pub async fn negotiate_feature<C>(
        stream: &mut XmppStream<C>,
        element: &Element,
        entity: &Option<Jid>,
    ) -> Result<Jid, Error>
    where
        C: Connection,
    {
        if element.name != "iq" && element.namespace.as_deref() != Some(namespaces::XMPP_CLIENT) {
            bail!("expected IQ stanza");
        }

        if element.attribute("type", None) != Some("set") {
            bail!("IQ stanza is not of type set");
        };

        let Some(request_id) = element.attribute("id", None) else {
            bail!("IQ stanza does not have an id");
        };

        let Some(bind_request) = element.child("bind", Some(namespaces::XMPP_BIND)) else {
            bail!("IQ stanza does not contain a bind request");
        };

        let resource = match bind_request.child("resource", Some(namespaces::XMPP_BIND)) {
            Some(requested_resource) => requested_resource.text(),
            None => uuid::Uuid::new_v4().to_string(),
        };

        let Some(entity) = entity else {
            bail!("entity to bind is unknown");
        };

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

        stream.writer().write_xml_element(&bind_response).await?;

        Ok(bound_entity)
    }
}
