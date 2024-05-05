use std::sync::Arc;

use anyhow::Error;
use futures::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::ServerConfig;

pub mod debug;
pub mod tcp;

pub trait Connection: AsyncRead + AsyncWrite + Unpin + Sized {
    type Upgrade: Future<Output = Result<Self, Error>> + Send + 'static;

    fn upgrade(self, config: Arc<ServerConfig>) -> Result<Self::Upgrade, Error>;
    fn is_starttls_allowed(&self) -> bool;
    fn is_secure(&self) -> bool;
    fn is_authenticated(&self) -> bool;
}
