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
};

use super::connection::Connection;

pub struct StarttlsNegotiator {
    _private: (),
}

impl StarttlsNegotiator {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn advertise_feature(&self) -> Element {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert(
            ("xmlns".to_string(), None),
            namespaces::XMPP_STARTTLS.to_string(),
        );

        Element {
            name: "starttls".to_string(),
            namespace: Some(namespaces::XMPP_STARTTLS.to_string()),
            attributes,
            children: vec![], // TODO: handle required starttls
        }
    }

    pub async fn starttls<C, P>(
        &self,
        mut stream_parser: P,
        mut stream_writer: StreamWriter<WriteHalf<C>>,
    ) -> Result<C, Error>
    where
        C: Connection,
        P: StreamParser<Reader = ReadHalf<C>>,
    {
        // TODO: initiate starttls on xmpp protocol level
        let Some(Ok(Frame::XmlFragment(starttls))) = stream_parser.next().await else {
            bail!("expected xml fragment");
        };

        if starttls.name != "starttls"
            || starttls.namespace != Some(namespaces::XMPP_STARTTLS.to_string())
        {
            bail!("expected starttls tag with correct namespace");
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

        stream_writer.write_xml_element(&starttls_proceed).await?;

        let reader = stream_parser.into_inner();
        let writer = stream_writer.into_inner();
        let socket = reader.unsplit(writer);

        socket
            .upgrade(get_settings().tls.server_config.clone())?
            .await
    }
}
