use futures::Future;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};

use crate::xmpp::jid::Jid;

enum Query {
    GetHashedPassword {
        jid: Jid,
        tx: oneshot::Sender<Option<String>>,
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
            Query::GetHashedPassword { jid, tx } => {
                let result = self.backend.get_hashed_password(jid).await;
                tx.send(result).unwrap();
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::DoNothing => {}
        }
    }
}

struct StoreHandle {
    queries: mpsc::Sender<Query>,
    commands: mpsc::Sender<Command>,
}

impl StoreHandle {
    fn new<B>(backend: B) -> Self
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

    async fn get_hashed_password(&mut self, jid: Jid) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        let msg = Query::GetHashedPassword { jid, tx };

        let _ = self.queries.send(msg).await;
        rx.await.expect("Store is gone")
    }
}

trait StoreBackend {
    fn get_hashed_password(&self, jid: Jid) -> impl Future<Output = Option<String>> + Send;
}

#[cfg(test)]
#[derive(Default)]
struct StubStoreBackend {
    hashed_password: Option<String>,
}

#[cfg(test)]
impl StoreBackend for StubStoreBackend {
    async fn get_hashed_password(&self, _jid: Jid) -> Option<String> {
        self.hashed_password.clone()
    }
}

#[cfg(test)]
mod test {
    use std::default::Default;

    use super::*;

    #[tokio::test]
    async fn test_store_query() {
        let expected_password = Some("password".to_string());
        let mut store = StoreHandle::new(StubStoreBackend {
            hashed_password: expected_password.clone(),
            ..Default::default()
        });
        let jid = "user@localhost/resource".parse::<Jid>().unwrap();
        let actual_password = store.get_hashed_password(jid).await;
        assert_eq!(expected_password, actual_password);
    }
}
