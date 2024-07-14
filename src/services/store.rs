use std::future::Future;

use scram_rs::{ScramSha1Ring, ScramSha256Ring};
use tokio::{
    select,
    sync::{mpsc, oneshot},
};

use crate::inbound::StoredPassword;
use crate::inbound::StoredPasswordArgon2;
use crate::inbound::StoredPasswordScram;
use crate::xmpp::jid::Jid;

enum Query {
    GetStoredPasswordArgon2 {
        jid: Jid,
        tx: oneshot::Sender<Option<StoredPasswordArgon2>>, // TODO: use Result instead of Option
    },
    GetStoredPasswordScramSha1 {
        jid: Jid,
        tx: oneshot::Sender<Option<StoredPasswordScram<ScramSha1Ring>>>, // TODO: use Result instead of Option
    },
    GetStoredPasswordScramSha256 {
        jid: Jid,
        tx: oneshot::Sender<Option<StoredPasswordScram<ScramSha256Ring>>>, // TODO: use Result instead of Option
    },
}

enum Command {
    DoNothing,
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
            Query::GetStoredPasswordArgon2 { jid, tx } => {
                let result = self
                    .backend
                    .get_stored_password_argon2(jid)
                    .await
                    .and_then(|s| s.as_str().parse::<StoredPasswordArgon2>().ok());
                tx.send(result).unwrap(); // TODO: handle error
            }
            Query::GetStoredPasswordScramSha1 { jid, tx } => {
                let result = self
                    .backend
                    .get_stored_password_scram_sha1(jid)
                    .await
                    .and_then(|s| {
                        s.as_str()
                            .parse::<StoredPasswordScram<ScramSha1Ring>>()
                            .ok()
                    });
                tx.send(result)
                    .unwrap_or_else(|_| panic!("could not return value for store query"));
                // TODO: handle error
            }
            Query::GetStoredPasswordScramSha256 { jid, tx } => {
                let result = self
                    .backend
                    .get_stored_password_scram_sha256(jid)
                    .await
                    .and_then(|s| {
                        s.as_str()
                            .parse::<StoredPasswordScram<ScramSha256Ring>>()
                            .ok()
                    });
                tx.send(result)
                    .unwrap_or_else(|_| panic!("could not return value for store query"));
                // TODO: handle error
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::DoNothing => {}
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

    pub async fn get_stored_password_argon2(&self, jid: Jid) -> Option<StoredPasswordArgon2> {
        let (tx, rx) = oneshot::channel();
        let msg = Query::GetStoredPasswordArgon2 { jid, tx };

        let _ = self.queries.send(msg).await;
        rx.await.expect("Store is gone")
    }

    pub async fn get_stored_password_scram_sha1(
        &self,
        jid: Jid,
    ) -> Option<StoredPasswordScram<ScramSha1Ring>> {
        let (tx, rx) = oneshot::channel();
        let msg = Query::GetStoredPasswordScramSha1 { jid, tx };

        let _ = self.queries.send(msg).await;
        rx.await.expect("Store is gone")
    }

    pub async fn get_stored_password_scram_sha256(
        &self,
        jid: Jid,
    ) -> Option<StoredPasswordScram<ScramSha256Ring>> {
        let (tx, rx) = oneshot::channel();
        let msg = Query::GetStoredPasswordScramSha256 { jid, tx };

        let _ = self.queries.send(msg).await;
        rx.await.expect("Store is gone")
    }
}

trait StoreBackend {
    fn get_stored_password_argon2(&self, jid: Jid) -> impl Future<Output = Option<String>> + Send;

    fn get_stored_password_scram_sha1(
        &self,
        jid: Jid,
    ) -> impl Future<Output = Option<String>> + Send;

    fn get_stored_password_scram_sha256(
        &self,
        jid: Jid,
    ) -> impl Future<Output = Option<String>> + Send;
}

// #[cfg(test)] // TODO: only compile this for tests
#[derive(Default)]
pub struct StubStoreBackend {
    pub hashed_password: Option<String>,
}

// #[cfg(test)] // TODO: only compile this for tests
impl StoreBackend for StubStoreBackend {
    async fn get_stored_password_argon2(&self, _jid: Jid) -> Option<String> {
        self.hashed_password.clone()
    }

    async fn get_stored_password_scram_sha1(&self, _jid: Jid) -> Option<String> {
        self.hashed_password.clone()
    }

    async fn get_stored_password_scram_sha256(&self, _jid: Jid) -> Option<String> {
        self.hashed_password.clone()
    }
}

#[cfg(test)]
mod test {
    use std::default::Default;

    use argon2::{Argon2, PasswordVerifier};

    use super::*;

    #[tokio::test]
    async fn test_store_query() {
        let mut store = StoreHandle::new(StubStoreBackend {
            hashed_password: Some(StoredPasswordArgon2::new("password").unwrap().to_string()),
            ..Default::default()
        });
        let jid = "user@localhost/resource".parse::<Jid>().unwrap();
        let stored_assword = store.get_stored_password_argon2(jid).await.unwrap();
        assert!(Argon2::default()
            .verify_password("password".as_bytes(), &stored_assword.hash.password_hash())
            .is_ok());
    }
}
