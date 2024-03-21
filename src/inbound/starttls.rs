use std::{fs::File, io::BufReader};

use anyhow::{bail, Error};
use rustls::pki_types::PrivateKeyDer::Pkcs8;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::io::{ReadHalf, WriteHalf};
use tokio_stream::StreamExt;

use crate::{
    settings::Tls,
    xml::{
        namespaces,
        stream_parser::{Frame, StreamParser},
        stream_writer::StreamWriter,
        Element,
    },
};

use super::connection::Connection;

pub struct StarttlsNegotiator<'s> {
    settings: &'s Tls,
}

impl<'s> StarttlsNegotiator<'s> {
    pub fn new(settings: &'s Tls) -> Self {
        Self { settings }
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
        C: Connection<Me = C>,
        P: StreamParser<Reader = ReadHalf<C>>,
    {
        // TODO: initiate starttls on xmpp protocol level
        let Some(Ok(Frame::XmlFragment(starttls))) = stream_parser.next().await else {
            bail!("expected xml fragment");
        };

        if starttls.name != "starttls"
            || starttls.namespace != Some(namespaces::XMPP_STARTTLS.to_string())
        {
            bail!("expected auth tag");
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

        // TODO: preload on server start to avoid blocking the executor. fail if the files are not found.
        let cert_file = &mut BufReader::new(File::open(&self.settings.cert_file_path)?);
        let key_file = &mut BufReader::new(File::open(&self.settings.key_file_path)?);

        let cert_chain = certs(cert_file).map(|result| result.unwrap()).collect();
        let key_der = pkcs8_private_keys(key_file)
            .map(|result| result.unwrap())
            .collect::<Vec<_>>()
            .remove(0); // TODO: avoid panics

        let reader = stream_parser.into_inner();
        let writer = stream_writer.into_inner();
        let socket = reader.unsplit(writer);

        socket.upgrade(cert_chain, Pkcs8(key_der))?.await
    }
}
