use anyhow::{Error, bail};
use tokio::io::ReadHalf;

use confidante_core::{
    xml::{Element, namespaces, stream_parser::StreamParser},
    xmpp::stream::{Connection, XmppStream},
};

pub(super) struct StarttlsNegotiator {
    _private: (),
}

impl StarttlsNegotiator {
    pub fn advertise_feature() -> Element {
        let mut starttls = Element::new("starttls", Some(namespaces::XMPP_STARTTLS));
        starttls.set_attribute("xmlns", None::<String>, namespaces::XMPP_STARTTLS);

        starttls
    }

    pub async fn negotiate_feature<C, P>(
        stream: &mut XmppStream<C, P>,
        element: &Element,
    ) -> Result<(), Error>
    where
        C: Connection,
        P: StreamParser<ReadHalf<C>>,
    {
        if element.validate("starttls", Some(namespaces::XMPP_STARTTLS)) {
            bail!("expected starttls element");
        }

        let mut starttls_proceed = Element::new("proceed", Some(namespaces::XMPP_STARTTLS));
        starttls_proceed.set_attribute("xmlns", None::<String>, namespaces::XMPP_STARTTLS);

        stream.writer().write_xml_element(&starttls_proceed).await?;
        stream.upgrade_to_tls().await?;

        Ok(())
    }
}
