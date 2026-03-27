use tokio::io::ReadHalf;

use confidante_core::{
    xml::{Element, namespaces, stream_parser::StreamParser},
    xmpp::stream::{Connection, StreamError, XmppStream},
};

use crate::{FeatureNegotiator, StreamFeature, StreamInfo};

pub(super) struct StarttlsNegotiator {
    _private: (),
}

impl StarttlsNegotiator {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl FeatureNegotiator for StarttlsNegotiator {
    fn advertise_feature(&self, _info: &StreamInfo) -> Element {
        let mut starttls = Element::new("starttls", Some(namespaces::XMPP_STARTTLS));
        starttls.set_attribute("xmlns", None::<String>, namespaces::XMPP_STARTTLS);

        starttls
    }

    async fn negotiate_feature<C, P>(
        &self,
        element: &Element,
        stream: &mut XmppStream<C, P>,
        info: &mut StreamInfo,
    ) -> Result<bool, StreamError>
    where
        C: Connection,
        P: StreamParser<ReadHalf<C>>,
    {
        if !element.validate("starttls", Some(namespaces::XMPP_STARTTLS)) {
            return Ok(false);
        }

        let mut starttls_proceed = Element::new("proceed", Some(namespaces::XMPP_STARTTLS));
        starttls_proceed.set_attribute("xmlns", None::<String>, namespaces::XMPP_STARTTLS);

        stream.writer().write_xml_element(&starttls_proceed).await?;
        stream.upgrade_to_tls().await?;

        info.features.insert(StreamFeature::Tls);

        Ok(true)
    }
}
