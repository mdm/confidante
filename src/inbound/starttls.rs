use anyhow::{bail, Error};
use tokio::io::{ReadHalf, WriteHalf};
use tokio_stream::StreamExt;

use crate::{
    settings::get_settings,
    xml::{
        namespaces,
        stream_parser::{Frame, StreamParser},
        stream_writer::StreamWriter,
        Element,
    },
    xmpp::stream::{Connection, XmppStream},
};

pub(super) struct StarttlsNegotiator {
    _private: (),
}

impl StarttlsNegotiator {
    pub fn advertise_feature() -> Element {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert(
            ("xmlns".to_string(), None),
            namespaces::XMPP_STARTTLS.to_string(),
        );

        Element {
            name: "starttls".to_string(),
            namespace: Some(namespaces::XMPP_STARTTLS.to_string()),
            attributes,
            children: vec![],
        }
    }

    pub async fn negotiate_feature<C>(
        stream: &mut XmppStream<C>,
        element: &Element,
    ) -> Result<(), Error>
    where
        C: Connection,
    {
        if element.name != "starttls"
            || element.namespace != Some(namespaces::XMPP_STARTTLS.to_string())
        {
            bail!("expected starttls element");
        }

        let starttls_proceed = Element {
            name: "proceed".to_string(),
            namespace: Some(namespaces::XMPP_STARTTLS.to_string()),
            attributes: vec![(
                ("xmlns".to_string(), None),
                namespaces::XMPP_STARTTLS.to_string(),
            )]
            .into_iter()
            .collect(),
            children: vec![],
        };

        stream.writer().write_xml_element(&starttls_proceed).await?;
        stream.upgrade_to_tls().await?;

        Ok(())
    }
}
