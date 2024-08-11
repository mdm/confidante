use std::future::Future;

use anyhow::Error;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};

use crate::inbound::StoredPasswordKind;
use crate::xmpp::jid::Jid;

pub use self::sqlite::SqliteStoreBackend;

mod fake;
mod sqlite;

enum Query {
    GetStoredPassword {
        jid: Jid,
        kind: StoredPasswordKind,
        result_tx: oneshot::Sender<Result<String, Error>>,
    },
}

enum Command {
    SetStoredPassword {
        jid: Jid,
        kind: StoredPasswordKind,
        stored_password: String,
        result_tx: oneshot::Sender<Result<(), Error>>,
    },
}

struct Store<B>
where
    B: StoreBackend,
{
    queries: mpsc::Receiver<Query>,
    commands: mpsc::Receiver<Command>,
    backend: B,
}

impl<B> Store<B>
where
    B: StoreBackend,
{
    async fn run(&mut self) {
        loop {
            select! {
                Some(query) = self.queries.recv() => {
                    self.handle_query(query).await;
                }
                Some(command) = self.commands.recv() => {
                    self.handle_command(command).await;
                }
            }
        }
    }

    async fn handle_query(&mut self, query: Query) {
        match query {
            Query::GetStoredPassword {
                jid,
                kind,
                result_tx,
            } => {
                let result = self.backend.get_stored_password(jid, kind).await;
                result_tx.send(result).unwrap(); // TODO: handle error
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::SetStoredPassword {
                jid,
                kind,
                stored_password,
                result_tx,
            } => {}
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoreHandle {
    queries: mpsc::Sender<Query>,
    commands: mpsc::Sender<Command>,
}

impl StoreHandle {
    pub fn new<B>(backend: B) -> Self
    where
        B: StoreBackend + Send + 'static,
    {
        let (queries_tx, queries_rx) = mpsc::channel(8);
        let (commands_tx, commands_rx) = mpsc::channel(8);
        let mut store = Store {
            queries: queries_rx,
            commands: commands_rx,
            backend,
        };
        tokio::spawn(async move {
            store.run().await;
        });

        StoreHandle {
            queries: queries_tx,
            commands: commands_tx,
        }
    }

    pub async fn get_stored_password(
        &self,
        jid: Jid,
        kind: StoredPasswordKind,
    ) -> Result<String, Error> {
        let (result_tx, result_rx) = oneshot::channel();
        let msg = Query::GetStoredPassword {
            jid,
            kind,
            result_tx,
        };

        let _ = self.queries.send(msg).await;
        result_rx.await.expect("Store is gone")
    }

    pub async fn set_stored_password(
        &self,
        jid: Jid,
        kind: StoredPasswordKind,
        stored_password: String,
    ) -> Result<(), Error> {
        let (result_tx, result_rx) = oneshot::channel();
        let msg = Command::SetStoredPassword {
            jid,
            kind,
            stored_password,
            result_tx,
        };

        let _ = self.commands.send(msg).await;
        result_rx.await.expect("Store is gone")
    }
}

trait StoreBackend {
    fn get_stored_password(
        &self,
        jid: Jid,
        kind: StoredPasswordKind,
    ) -> impl Future<Output = Result<String, Error>> + Send;

    fn set_stored_password(
        &mut self,
        jid: Jid,
        kind: StoredPasswordKind,
        stored_password: String,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

#[cfg(test)]
mod test {
    use std::default::Default;

    use argon2::{Argon2, PasswordVerifier};

    use crate::inbound::StoredPassword;
    use crate::inbound::StoredPasswordArgon2;

    use self::fake::FakeStoreBackend;

    use super::*;

    #[tokio::test]
    async fn test_store_query() {
        let mut store = StoreHandle::new(FakeStoreBackend {
            stored_password_argon2: Some(
                StoredPasswordArgon2::new("password").unwrap().to_string(),
            ),
            ..Default::default()
        });
        let jid = "user@localhost/resource".parse::<Jid>().unwrap();
        let stored_assword = store
            .get_stored_password(jid, StoredPasswordKind::Argon2)
            .await
            .unwrap()
            .parse::<StoredPasswordArgon2>()
            .unwrap();
        assert!(Argon2::default()
            .verify_password("password".as_bytes(), &stored_assword.hash.password_hash())
            .is_ok());
    }
}
