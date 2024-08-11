mod inbound; // TODO: rename to inbound
mod services;
mod settings;
mod types;
mod utils;
mod xml;
mod xmpp;

use scram_rs::ScramSha1Ring;

use inbound::connection::debug::DebugConnection;
use inbound::connection::tcp::TcpConnection;
use inbound::{StoredPassword, StoredPasswordScram};
use services::router::RouterHandle;
use services::store::{FakeStoreBackend, StoreHandle};
use settings::Settings;

use crate::inbound::InboundStream;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    Settings::init()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5222").await?;

    let router = RouterHandle::new();
    let stored_password_scram_sha1 =
        Some(StoredPasswordScram::<ScramSha1Ring>::new("password")?.to_string());
    let store_backend = FakeStoreBackend {
        stored_password_scram_sha1,
        ..Default::default()
    };
    let store = StoreHandle::new(store_backend);

    loop {
        let (connection, _) = listener.accept().await?;

        // TODO: handle shutdown

        let router = router.clone();
        let store = store.clone();

        tokio::spawn(async move {
            let connection = TcpConnection::new(connection, true);
            let connection = DebugConnection::try_new(connection).await.unwrap();
            println!("New connection: {}", connection.uuid());

            let mut stream = InboundStream::new(connection, router, store);
            stream.handle().await;

            // TODO: close connection (or does drop do that?)
        });
    }
}
