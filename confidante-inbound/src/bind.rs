use anyhow::{Error, bail};
use tokio::io::ReadHalf;

use confidante_core::{
    xml::{Element, namespaces, stream_parser::StreamParser},
    xmpp::{
        jid::Jid,
        stream::{Connection, XmppStream},
    },
};

pub struct ResourceBindingNegotiator {
    _private: (),
}

impl ResourceBindingNegotiator {
    pub fn advertise_feature() -> Element {
        let mut bind = Element::new("bind", Some(namespaces::XMPP_BIND));
        bind.set_attribute("xmlns", None::<String>, namespaces::XMPP_BIND);

        bind
    }

    pub async fn negotiate_feature<C, P>(
        stream: &mut XmppStream<C, P>,
        element: &Element,
        entity: &Option<Jid>,
    ) -> Result<Jid, Error>
    where
        C: Connection,
        P: StreamParser<ReadHalf<C>>,
    {
        if element.validate("iq", Some(namespaces::XMPP_CLIENT)) {
            bail!("expected IQ stanza");
        }

        if element.attribute("type", None::<String>) != Some("set") {
            bail!("IQ stanza is not of type set");
        };

        let Some(request_id) = element.attribute("id", None::<String>) else {
            bail!("IQ stanza does not have an id");
        };

        let Some(bind_request) = element.find_child("bind", Some(namespaces::XMPP_BIND)) else {
            bail!("IQ stanza does not contain a bind request");
        };

        let resource = match bind_request.find_child("resource", Some(namespaces::XMPP_BIND)) {
            Some(requested_resource) => requested_resource.text(),
            None => uuid::Uuid::new_v4().to_string(),
        };

        let Some(entity) = entity else {
            bail!("entity to bind is unknown");
        };

        let bound_entity = entity.bind(resource);

        let mut bind_response = Element::new("iq", None::<String>);
        bind_response.set_attribute("id", None::<String>, request_id);
        bind_response.set_attribute("type", None::<String>, "result");
        bind_response.with_child("bind", Some(namespaces::XMPP_BIND), |bind| {
            bind.set_attribute("xmlns", None::<String>, namespaces::XMPP_BIND);
            bind.with_child("jid", None::<String>, |jid| {
                jid.add_text(format!("{}", bound_entity));
            });
        });

        stream.writer().write_xml_element(&bind_response).await?;

        Ok(bound_entity)
    }
}
