use clap::{Parser, Subcommand};

use confidante_backend::settings::Settings;
use confidante_backend::store::{SqliteStoreBackend, StoreHandle};
use confidante_core::xml::stream_parser::rusty_xml::RustyXmlStreamParser;
use confidante_core::xmpp::jid::Jid;
use confidante_inbound::connection::debug::DebugConnection;
use confidante_inbound::connection::tcp::TcpConnection;
use confidante_inbound::{ConnectionType, InboundStreamSettings};
use confidante_inbound::{
    InboundStream,
    sasl::{StoredPassword, StoredPasswordArgon2, StoredPasswordScram},
};
use confidante_services::router::RouterHandle;
use sha1::Sha1;
use sha2::Sha256;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    AddUser { bare_jid: String, password: String },
    RemoveUser { bare_jid: String },
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let settings = Settings::init()?;

    let store_backend = SqliteStoreBackend::new(&settings).await?;
    let store = StoreHandle::new(store_backend);

    let cli = Cli::parse();
    match cli.command {
        Some(Commands::AddUser { bare_jid, password }) => {
            let bare_jid = bare_jid.parse::<Jid>()?.to_bare();
            let stored_password_argon2 = StoredPasswordArgon2::new(&password)?.to_string();
            let stored_password_scram_sha1 =
                StoredPasswordScram::<Sha1>::new(&password)?.to_string();
            let stored_password_scram_sha256 =
                StoredPasswordScram::<Sha256>::new(&password)?.to_string();
            store
                .add_user(
                    bare_jid,
                    stored_password_argon2,
                    stored_password_scram_sha1,
                    stored_password_scram_sha256,
                )
                .await?;
        }
        Some(Commands::RemoveUser { bare_jid }) => {
            let bare_jid = bare_jid.parse::<Jid>()?.to_bare();
            store.remove_user(bare_jid).await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:5222").await?;

            let router = RouterHandle::new();

            loop {
                let (connection, _) = listener.accept().await?;

                let settings = settings.clone();
                let router = router.clone();
                let store = store.clone();

                tokio::spawn(async move {
                    let connection =
                        TcpConnection::new(connection, settings.tls.server_config.clone(), true);
                    let connection = DebugConnection::try_new(connection).await.unwrap();
                    println!("New connection: {}", connection.uuid());

                    let settings = InboundStreamSettings {
                        connection_type: ConnectionType::Client,
                        domain: settings.domain.clone(),
                        tls_required: settings.tls.required_for_clients,
                    };
                    let mut stream = InboundStream::<_, RustyXmlStreamParser<_>, _>::new(
                        connection, router, store, settings,
                    );
                    stream.handle().await;
                });
            }
        }
    }

    Ok(())
}
