use anyhow::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{Connection, ConnectionType};

pub struct FakeConnection {
    inner: tokio::io::DuplexStream,
    connection_type: ConnectionType,
    starttls_allowed: bool,
    secure: bool,
    authenticated: bool,
}

impl FakeConnection {
    pub fn new(server: tokio::io::DuplexStream, connection_type: ConnectionType) -> Self {
        Self {
            inner: server,
            connection_type,
            starttls_allowed: true,
            secure: false,
            authenticated: false,
        }
    }

    pub fn set_starttls_allowed(&mut self, starttls_allowed: bool) {
        self.starttls_allowed = starttls_allowed;
    }

    pub fn set_secure(&mut self, secure: bool) {
        self.secure = secure;
    }

    pub fn set_authenticated(&mut self, authenticated: bool) {
        self.authenticated = authenticated;
    }
}

impl AsyncRead for FakeConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FakeConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for FakeConnection {
    type Upgrade = TestConnectionUpgrade;

    fn connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    fn upgrade(self) -> Result<Self::Upgrade, Error> {
        Ok(TestConnectionUpgrade {
            connection: Some(self),
        })
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

pub struct TestConnectionUpgrade {
    connection: Option<FakeConnection>,
}

impl Future for TestConnectionUpgrade {
    type Output = Result<FakeConnection, Error>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut connection = self
            .connection
            .take()
            .expect("TestConnectionUpgrade polled without an inner connection");
        connection.secure = true;
        std::task::Poll::Ready(Ok(connection))
    }
}
