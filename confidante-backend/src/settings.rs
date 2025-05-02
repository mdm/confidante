use std::sync::Arc;
use std::{fs::File, io::BufReader};

use anyhow::{Error, anyhow};
use rustls_native_certs::load_native_certs;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Deserializer};
use tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

use confidante_core::xmpp::jid::Jid;

#[derive(Debug, Deserialize)]

struct TlsConfig {
    #[serde(deserialize_with = "load_certificate_chain")]
    certificate_chain: Vec<CertificateDer<'static>>,
    #[serde(deserialize_with = "load_private_key")]
    private_key: PrivateKeyDer<'static>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsSettings {
    pub required_for_clients: bool,
    pub required_for_servers: bool,
    #[serde(deserialize_with = "init_tls_server_config")]
    pub server_config: Arc<ServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub database_url: String,
    #[serde(deserialize_with = "deserialize_jid")]
    pub domain: Jid,
    pub tls: TlsSettings,
}

impl Settings {
    pub fn init() -> Result<Self, Error> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config/defaults"))
            .add_source(config::File::with_name("config/overrides"))
            .add_source(config::Environment::with_prefix("CONFIDANTE").separator("__"))
            .build()?;

        let settings = settings.try_deserialize().map_err(|e| anyhow!(e))?;

        Ok(settings)
    }
}

fn load_certificate_chain<'d, D: Deserializer<'d>>(
    deserializer: D,
) -> Result<Vec<CertificateDer<'static>>, D::Error> {
    let cert_path = String::deserialize(deserializer)?;
    let cert_file = &mut BufReader::new(File::open(cert_path).map_err(serde::de::Error::custom)?);
    let cert_chain = certs(cert_file).map(|result| result.unwrap()).collect();

    Ok(cert_chain)
}

fn load_private_key<'d, D: Deserializer<'d>>(
    deserializer: D,
) -> Result<PrivateKeyDer<'static>, D::Error> {
    let key_path = String::deserialize(deserializer)?;
    let key_file = &mut BufReader::new(File::open(key_path).map_err(serde::de::Error::custom)?);
    let key_der = pkcs8_private_keys(key_file)
        .map(|result| result.unwrap())
        .collect::<Vec<_>>()
        .remove(0);

    Ok(Pkcs8(key_der))
}

fn init_tls_server_config<'d, D: Deserializer<'d>>(
    deserializer: D,
) -> Result<Arc<ServerConfig>, D::Error> {
    let config = TlsConfig::deserialize(deserializer)?;

    let mut root_cert_store = RootCertStore::empty();
    for cert in load_native_certs().certs {
        root_cert_store
            .add(cert)
            .map_err(serde::de::Error::custom)?;
    }
    let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_store))
        .allow_unauthenticated()
        .build()
        .map_err(serde::de::Error::custom)?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(config.certificate_chain, config.private_key)
        .map_err(serde::de::Error::custom)?;

    Ok(Arc::new(config))
}

fn deserialize_jid<'d, D: Deserializer<'d>>(
    deserializer: D,
) -> Result<Jid, D::Error> {
    let raw_jid = String::deserialize(deserializer)?;
    raw_jid
        .parse::<Jid>()
        .map_err(serde::de::Error::custom)
}
