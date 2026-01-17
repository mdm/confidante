use std::future::Future;

use anyhow::Error;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};

use confidante_core::xmpp::jid::Jid;
use confidante_inbound::sasl::StoredPasswordLookup;

pub use self::sqlite::SqliteStoreBackend;

mod fake;
mod sqlite;

#[derive(Debug)]
pub enum StoredPasswordKind {
    Argon2,
    ScramSha1,
    ScramSha256,
}

enum Query {
    GetStoredPassword {
        jid: Jid,
        kind: StoredPasswordKind,
        result_tx: oneshot::Sender<Result<String, Error>>,
    },
}

enum Command {
    AddUser {
        jid: Jid,
        stored_password_argon2: String,
        stored_password_scram_sha1: String,
        stored_password_scram_sha256: String,
        result_tx: oneshot::Sender<Result<(), Error>>,
    },
    RemoveUser {
        jid: Jid,
        result_tx: oneshot::Sender<Result<(), Error>>,
    },
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
                else => break,
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
                result_tx.send(result).unwrap();
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::AddUser {
                jid,
                stored_password_argon2,
                stored_password_scram_sha1,
                stored_password_scram_sha256,
                result_tx,
            } => {
                let result = self
                    .backend
                    .add_user(
                        jid,
                        stored_password_argon2,
                        stored_password_scram_sha1,
                        stored_password_scram_sha256,
                    )
                    .await;
                result_tx.send(result).unwrap();
            }
            Command::RemoveUser { jid, result_tx } => {
                let result = self.backend.remove_user(jid).await;
                result_tx.send(result).unwrap();
            }
            Command::SetStoredPassword {
                jid,
                kind,
                stored_password,
                result_tx,
            } => {
                let result = self
                    .backend
                    .set_stored_password(jid, kind, stored_password)
                    .await;
                result_tx.send(result).unwrap();
            }
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

    pub async fn add_user(
        &self,
        jid: Jid,
        stored_password_argon2: String,
        stored_password_scram_sha1: String,
        stored_password_scram_sha256: String,
    ) -> Result<(), Error> {
        let (result_tx, result_rx) = oneshot::channel();
        let msg = Command::AddUser {
            jid,
            stored_password_argon2,
            stored_password_scram_sha1,
            stored_password_scram_sha256,
            result_tx,
        };

        let _ = self.commands.send(msg).await;
        result_rx.await.expect("Store is gone")
    }

    pub async fn remove_user(&self, jid: Jid) -> Result<(), Error> {
        let (result_tx, result_rx) = oneshot::channel();
        let msg = Command::RemoveUser { jid, result_tx };

        let _ = self.commands.send(msg).await;
        result_rx.await.expect("Store is gone")
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

impl StoredPasswordLookup for StoreHandle {
    fn get_stored_password_argon2(
        &self,
        jid: Jid,
    ) -> impl std::future::Future<Output = Result<String, anyhow::Error>> + Send {
        self.get_stored_password(jid, StoredPasswordKind::Argon2)
    }

    fn get_stored_password_scram_sha1(
        &self,
        jid: Jid,
    ) -> impl std::future::Future<Output = Result<String, anyhow::Error>> + Send {
        self.get_stored_password(jid, StoredPasswordKind::ScramSha1)
    }

    fn get_stored_password_scram_sha256(
        &self,
        jid: Jid,
    ) -> impl std::future::Future<Output = Result<String, anyhow::Error>> + Send {
        self.get_stored_password(jid, StoredPasswordKind::ScramSha256)
    }
}

trait StoreBackend {
    fn add_user(
        &mut self,
        jid: Jid,
        stored_password_argon2: String,
        stored_password_scram_sha1: String,
        stored_password_scram_sha256: String,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    fn remove_user(&mut self, jid: Jid) -> impl Future<Output = Result<(), Error>> + Send;

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

    use self::fake::FakeStoreBackend;

    use super::*;

    #[tokio::test]
    async fn test_store_query() {
        let stored_password_argon2 = "super secret password";
        let mut store = StoreHandle::new(FakeStoreBackend {
            stored_password_argon2: Some(stored_password_argon2.to_string()),
            ..Default::default()
        });
        let jid = "user@localhost/resource".parse::<Jid>().unwrap();
        let retrieved_password = store
            .get_stored_password(jid, StoredPasswordKind::Argon2)
            .await
            .unwrap();
        assert_eq!(stored_password_argon2, retrieved_password);
    }
}
