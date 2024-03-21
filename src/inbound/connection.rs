use anyhow::Error;
use futures::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub mod debug;
pub mod tcp;

pub trait Connection: AsyncRead + AsyncWrite + Unpin {
    type Me: Sized;
    type Upgrade: Future<Output = Result<Self::Me, Error>> + Send + 'static;

    fn upgrade(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Self::Upgrade, Error>;
    fn is_starttls_allowed(&self) -> bool;
    fn is_secure(&self) -> bool;
    fn is_authenticated(&self) -> bool;
}
