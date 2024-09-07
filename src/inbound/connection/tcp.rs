use std::{pin::Pin, sync::Arc, task::ready};

use anyhow::{anyhow, Error};
use futures::Future;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{rustls::ServerConfig, server::TlsStream, Accept, TlsAcceptor};

use crate::xmpp::stream::Connection;

enum Socket {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

pub struct TcpConnection {
    socket: Socket,
    starttls_allowed: bool,
}

impl TcpConnection {
    pub fn new(socket: TcpStream, starttls_allowed: bool) -> Self {
        let socket = Socket::Plain(socket);

        TcpConnection {
            socket,
            starttls_allowed,
        }
    }
}

impl Connection for TcpConnection {
    type Upgrade = TcpConnectionUpgrade;

    fn upgrade(self, config: Arc<ServerConfig>) -> Result<Self::Upgrade, Error> {
        match self.socket {
            Socket::Plain(socket) => {
                let accept = TlsAcceptor::from(config).accept(socket);

                Ok(TcpConnectionUpgrade { accept })
            }
            Socket::Tls(_) => Err(anyhow!("Connection is already secure")),
        }
    }

    fn is_starttls_allowed(&self) -> bool {
        self.starttls_allowed
    }

    fn is_secure(&self) -> bool {
        matches!(self.socket, Socket::Tls(_))
    }

    fn is_authenticated(&self) -> bool {
        match &self.socket {
            Socket::Plain(_) => false,
            Socket::Tls(socket) => socket.get_ref().1.peer_certificates().is_some(),
        }
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.socket {
            Socket::Plain(socket) => Pin::new(socket).poll_read(cx, buf),
            Socket::Tls(socket) => Pin::new(socket).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut self.socket {
            Socket::Plain(socket) => Pin::new(socket).poll_write(cx, buf),
            Socket::Tls(socket) => Pin::new(socket).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.socket {
            Socket::Plain(socket) => Pin::new(socket).poll_flush(cx),
            Socket::Tls(socket) => Pin::new(socket).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.socket {
            Socket::Plain(socket) => Pin::new(socket).poll_shutdown(cx),
            Socket::Tls(socket) => Pin::new(socket).poll_shutdown(cx),
        }
    }
}

pub struct TcpConnectionUpgrade {
    accept: Accept<TcpStream>,
}

impl Future for TcpConnectionUpgrade {
    type Output = Result<TcpConnection, Error>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let tls_stream = ready!(Pin::new(&mut self.accept).poll(cx))?;
        let connection = TcpConnection {
            socket: Socket::Tls(tls_stream),
            starttls_allowed: false,
        };
        std::task::Poll::Ready(Ok(connection))
    }
}
