use anyhow::{anyhow, bail, Error};
use base64::prelude::*;
use rand::{RngCore, SeedableRng};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::xml::Element;
use crate::xmpp::stream_header::StreamHeader;

struct StreamWriter<'w, W: AsyncWrite + Unpin> {
    writer: &'w mut W,
}

impl<'w, W: AsyncWrite + Unpin> StreamWriter<'w, W> {
    pub fn new(writer: &mut W) -> Self {
        Self { writer }
    }

    pub async fn write_stream_header(
        &mut self,
        header: &StreamHeader,
        include_xml_declaration: bool,
    ) -> Result<(), Error> {
        if include_xml_declaration {
            self.write_xml_declaration().await?;
        }

        let Some(ref from) = header.from else {
            bail!("`from` field is required in outgoing stream header");
        };

        let mut rng = rand_chacha::ChaCha20Rng::from_entropy(); // TODO: use UUID instead?
        let mut id_raw = [0u8; 16];
        rng.fill_bytes(&mut id_raw);
        let id_encoded = BASE64_STANDARD.encode(id_raw);

        let formatted_header = format!(
            r#"<stream:stream from="{}" id="{}" version="1.0" xml:lang="en" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams">"#,
            from, id_encoded
        );

        self.write_str(&formatted_header).await
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.writer
            .write_all(bytes)
            .await
            .map_err(|err| anyhow!(err))
    }

    async fn write_str(&mut self, string: &str) -> Result<(), Error> {
        self.write_bytes(string.as_bytes()).await
    }

    async fn write_xml_declaration(&mut self) -> Result<(), Error> {
        self.write_str("<?xml version='1.0'?>")
            .await
    }

    async fn write_xml_element(&mut self, element: &Element) -> Result<(), Error> {
        self.write_str(&element.to_string())
            .await
    }
}
