use std::{fmt::Display, future::Future};

use anyhow::Error;
use base64::prelude::*;
use rand::{RngCore, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf, split};

use crate::xml::{stream_parser::StreamParser, stream_writer::StreamWriter};

#[derive(Debug, Clone)]
pub struct StreamId(String);

impl StreamId {
    pub fn new() -> Self {
        let id = Self::generate_id();
        Self(id)
    }

    fn generate_id() -> String {
        let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();
        let mut id_raw = [0u8; 16];
        rng.fill_bytes(&mut id_raw);

        BASE64_STANDARD.encode(id_raw)
    }
}

impl Default for StreamId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait Connection: AsyncRead + AsyncWrite + Unpin + Sized {
    type Upgrade: Future<Output = Result<Self, Error>> + Send + 'static;

    fn upgrade(self) -> Result<Self::Upgrade, Error>;
    fn is_starttls_allowed(&self) -> bool;
    fn is_secure(&self) -> bool;
    fn is_authenticated(&self) -> bool;
}

pub struct XmppStream<C, P>
where
    C: Connection,
    P: StreamParser<ReadHalf<C>>,
{
    starttls_allowed: bool,
    secure: bool,
    authenticated: bool,
    reader: Option<P>,
    writer: Option<StreamWriter<WriteHalf<C>>>,
}

impl<C, P> XmppStream<C, P>
where
    C: Connection,
    P: StreamParser<ReadHalf<C>>,
{
    pub fn new(connection: C) -> Self {
        let starttls_allowed = connection.is_starttls_allowed();
        let secure = connection.is_secure();
        let authenticated = connection.is_authenticated();
        let (reader, writer) = split(connection);
        let reader = Some(P::new(reader));
        let writer = Some(StreamWriter::new(writer));

        Self {
            starttls_allowed,
            secure,
            authenticated,
            reader,
            writer,
        }
    }

    pub fn reset(&mut self) {
        let reader = self.reader.take().unwrap().into_inner();
        let writer = self.writer.take().unwrap().into_inner();
        self.reader = Some(P::new(reader));
        self.writer = Some(StreamWriter::new(writer));
    }

    pub fn is_starttls_allowed(&self) -> bool {
        self.starttls_allowed
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn reader(&mut self) -> &mut P {
        self.reader.as_mut().unwrap()
    }

    pub fn writer(&mut self) -> &mut StreamWriter<WriteHalf<C>> {
        self.writer.as_mut().unwrap()
    }

    pub async fn upgrade_to_tls(&mut self) -> Result<(), Error> {
        let reader = self.reader.take().unwrap().into_inner();
        let writer = self.writer.take().unwrap().into_inner();
        let connection = reader.unsplit(writer);

        let connection = connection.upgrade()?.await?;

        self.starttls_allowed = connection.is_starttls_allowed();
        self.secure = connection.is_secure();
        self.authenticated = connection.is_authenticated();

        let (reader, writer) = split(connection);
        self.reader = Some(P::new(reader));
        self.writer = Some(StreamWriter::new(writer));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::xml::stream_parser::rusty_xml::RustyXmlStreamParser;

    use super::*;

    #[derive(Default)]
    struct DummyConnection {
        starttls_allowed: bool,
        secure: bool,
        authenticated: bool,
    }

    impl AsyncRead for DummyConnection {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DummyConnection {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(0))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl Connection for DummyConnection {
        type Upgrade = std::future::Ready<Result<Self, Error>>;

        fn upgrade(mut self) -> Result<Self::Upgrade, Error> {
            self.secure = true;
            Ok(std::future::ready(Ok(self)))
        }

        fn is_starttls_allowed(&self) -> bool {
            self.starttls_allowed
        }

        fn is_secure(&self) -> bool {
            self.secure
        }

        fn is_authenticated(&self) -> bool {
            self.authenticated
        }
    }

    #[tokio::test]
    async fn upgrade_works() {
        let mut stream = XmppStream::<_, RustyXmlStreamParser<_>>::new(DummyConnection::default());
        assert!(!stream.is_secure());
        stream.upgrade_to_tls().await.unwrap();
        assert!(stream.is_secure());
    }

    #[test]
    fn reader_is_available_after_new() {
        let stream = XmppStream::<_, RustyXmlStreamParser<_>>::new(DummyConnection::default());
        assert!(stream.reader.is_some());
    }

    #[test]
    fn writer_is_available_after_new() {
        let stream = XmppStream::<_, RustyXmlStreamParser<_>>::new(DummyConnection::default());
        assert!(stream.writer.is_some());
    }

    #[test]
    fn reader_is_available_after_reset() {
        let mut stream = XmppStream::<_, RustyXmlStreamParser<_>>::new(DummyConnection::default());
        stream.reset();
        assert!(stream.reader.is_some());
    }

    #[test]
    fn writer_is_available_after_reset() {
        let mut stream = XmppStream::<_, RustyXmlStreamParser<_>>::new(DummyConnection::default());
        stream.reset();
        assert!(stream.writer.is_some());
    }

    #[tokio::test]
    async fn reader_is_available_after_upgrade() {
        let mut stream = XmppStream::<_, RustyXmlStreamParser<_>>::new(DummyConnection::default());
        stream.upgrade_to_tls().await.unwrap();
        assert!(stream.reader.is_some());
    }

    #[tokio::test]
    async fn writer_is_available_after_upgrade() {
        let mut stream = XmppStream::<_, RustyXmlStreamParser<_>>::new(DummyConnection::default());
        stream.upgrade_to_tls().await.unwrap();
        assert!(stream.writer.is_some());
    }
}
