mod inbound;
mod services;
mod settings;
mod types;
mod utils;
mod xml;
mod xmpp;

use clap::{Parser, Subcommand};
use inbound::connection::debug::DebugConnection;
use inbound::connection::tcp::TcpConnection;
use inbound::{StoredPassword, StoredPasswordArgon2, StoredPasswordScram};
use scram_rs::{ScramSha1Ring, ScramSha256Ring};
use services::router::RouterHandle;
use services::store::{SqliteStoreBackend, StoreHandle};
use settings::Settings;
use xml::stream_parser::rusty_xml::RustyXmlStreamParser;
use xmpp::jid::Jid;

use crate::inbound::InboundStream;

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
                StoredPasswordScram::<ScramSha1Ring>::new(&password)?.to_string();
            let stored_password_scram_sha256 =
                StoredPasswordScram::<ScramSha256Ring>::new(&password)?.to_string();
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

                    let mut stream = InboundStream::<_, RustyXmlStreamParser<_>>::new(
                        connection, router, store, settings,
                    );
                    stream.handle().await;
                });
            }
        }
    }

    Ok(())
}
