use anyhow::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub mod debug;
pub mod tcp;

trait Connection: AsyncRead + AsyncWrite + Unpin {
    type Upgrade;

    fn upgrade(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Self::Upgrade, Error>;
    fn is_secure(&self) -> bool;
    fn is_authenticated(&self) -> bool;
}
