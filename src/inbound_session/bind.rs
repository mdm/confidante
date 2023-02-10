use anyhow::{Error, bail};

use crate::xml_stream_parser::XmlFrame;

use super::sasl::AuthenticatedEntity;
use super::session::Session;

#[derive(Debug)]
pub struct BoundResource(pub String, ());


pub struct ResourceBindingNegotiator {
    _private: (),
}

impl ResourceBindingNegotiator {
    pub fn new() -> Self {
        Self {
            _private: (),
        }
    }

    pub async fn advertise_feature(&self, session: &mut Session) -> Result<(), Error> { // TODO: decide if this should be part of a trait
        session.write_bytes("<bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"/>\n".as_bytes()).await?;
        Ok(())
    }

    pub async fn bind_resource(&self, entity: &AuthenticatedEntity, session: &mut Session) -> Result<BoundResource, Error> {
        let iq_stanza = match session.read_frame().await? {
            Some(XmlFrame::XmlFragment(fragment)) => fragment,
            _ => bail!("expected xml fragment"),
        };
        dbg!(&iq_stanza);

        if iq_stanza.name != "iq" {
            bail!("expected IQ stanza");
        }

        if iq_stanza.get_attribute("type", None) != Some("set") {
            bail!("IQ stanza is not of type set");
        };

        let Some(request_id) = iq_stanza.get_attribute("id", None) else {
            bail!("IQ stanza does not have an id");
        };

        let Some(bind_request) = iq_stanza.get_child("bind", Some("urn:ietf:params:xml:ns:xmpp-bind")) else {
            bail!("IQ stanza does not contain a bind request");
        };

        let resource = match bind_request.get_child("resource", Some("urn:ietf:params:xml:ns:xmpp-bind")) {
            Some(requested_resource) => requested_resource.content_str(),
            None => uuid::Uuid::new_v4().to_string(),
        };

        // TODO: check resource availability and maximum number of connected resources

        session.write_bytes(format!("<iq id=\"{request_id}\" type=\"result\">\n").as_bytes()).await?;
        session.write_bytes("    <bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\">\n".as_bytes()).await?;
        session.write_bytes(format!("        <jid>{}@localhost/{}</jid>\n", entity.0, resource).as_bytes()).await?; // TODO: don't hard-code domain
        session.write_bytes("    </bind>\n".as_bytes()).await?;
        session.write_bytes("</iq>\n".as_bytes()).await?;

        Ok(BoundResource(resource, ()))
    }
}
