use crate::xmpp::jid::Jid;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Tls {
    pub required_for_clients: bool,
    pub required_for_servers: bool,
    pub cert_file_path: String,
    pub key_file_path: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Settings {
    pub domain: Jid, // TODO: can we deserialize this into a Jid?
    pub tls: Tls,
}

impl Settings {
    pub fn new() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config/defaults"))
            .add_source(config::File::with_name("config/overrides"))
            .build()?;

        settings.try_deserialize()
    }
}
