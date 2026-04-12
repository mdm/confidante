use anyhow::anyhow;
use confidante_services::router::ManagementCommand;
use tokio::{io::ReadHalf, sync::mpsc};

use confidante_core::{
    xml::{Element, namespaces, stream_parser::StreamParser},
    xmpp::{
        stanza::Stanza,
        stream::{Connection, StreamError, XmppStream},
    },
};

use crate::{FeatureNegotiator, StreamFeature, StreamInfo};

pub struct ResourceBindingNegotiator {
    router_management: mpsc::Sender<ManagementCommand>,
    stanza_tx: mpsc::Sender<Stanza>,
}

impl ResourceBindingNegotiator {
    pub fn new(
        router_management: mpsc::Sender<ManagementCommand>,
        stanza_tx: mpsc::Sender<Stanza>,
    ) -> Self {
        Self {
            router_management,
            stanza_tx,
        }
    }
}

#[async_trait::async_trait]
impl<C, P> FeatureNegotiator<C, P> for ResourceBindingNegotiator
where
    C: Connection + Send,
    P: StreamParser<ReadHalf<C>> + Send,
{
    fn advertise_feature(&self, info: &StreamInfo) -> Element {
        let mut bind = Element::new("bind", Some(namespaces::XMPP_BIND));
        bind.set_attribute("xmlns", None::<String>, namespaces::XMPP_BIND);

        bind
    }

    async fn negotiate_feature(
        &self,
        element: &Element,
        stream: &mut XmppStream<C, P>,
        info: &mut StreamInfo,
    ) -> Result<bool, StreamError> {
        if !element.validate("iq", Some(namespaces::XMPP_CLIENT)) {
            return Ok(false);
        }

        if element.attribute("type", None::<String>) != Some("set") {
            return Ok(false);
        };

        let Some(request_id) = element.attribute("id", None::<String>) else {
            return Ok(false);
        };

        let Some(bind_request) = element.find_child("bind", Some(namespaces::XMPP_BIND)) else {
            return Ok(false);
        };

        let resource = match bind_request.find_child("resource", Some(namespaces::XMPP_BIND)) {
            Some(requested_resource) => requested_resource.text(),
            None => uuid::Uuid::new_v4().to_string(),
        };

        info.peer_jid = info
            .peer_jid
            .as_ref()
            .map(|jid| jid.with_resource(Some(resource)));

        let Some(peer_jid) = &info.peer_jid else {
            // This should never happen. Peer JID should have been set during authentication.
            return Err(anyhow!("JID was not set before resource binding").into());
        };

        self.router_management
            .send(ManagementCommand::Register(
                peer_jid.clone(),
                self.stanza_tx.clone(),
            ))
            .await
            .unwrap();

        let mut bind_response = Element::new("iq", None::<String>);
        bind_response.set_attribute("id", None::<String>, request_id);
        bind_response.set_attribute("type", None::<String>, "result");
        bind_response.with_child("bind", Some(namespaces::XMPP_BIND), |bind| {
            bind.set_attribute("xmlns", None::<String>, namespaces::XMPP_BIND);
            bind.with_child("jid", None::<String>, |jid| {
                jid.add_text(format!("{}", peer_jid));
            });
        });

        stream.writer().write_xml_element(&bind_response).await?;

        info.features.insert(StreamFeature::ResourceBinding);

        Ok(true)
    }
}
