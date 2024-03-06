use std::collections::HashMap;

use tokio::{select, sync::mpsc};

use crate::xmpp::{jid::Jid, stanza::Stanza};

#[derive(Debug)]
pub enum ManagementCommand {
    Register(Jid, mpsc::Sender<Stanza>),
    Unregister(Jid),
}

struct Router {
    stanzas: mpsc::Receiver<Stanza>,
    management: mpsc::Receiver<ManagementCommand>,
    entities: HashMap<Jid, mpsc::Sender<Stanza>>,
}

impl Router {
    async fn run(&mut self) {
        loop {
            select! {
                Some(stanza) = self.stanzas.recv() => {
                    self.route_stanza(stanza).await;
                }
                Some(command) = self.management.recv() => {
                    self.handle_management_command(command).await;
                }
            }
        }
    }

    async fn route_stanza(&mut self, stanza: Stanza) {
        dbg!(stanza);
    }

    async fn handle_management_command(&mut self, command: ManagementCommand) {
        match command {
            ManagementCommand::Register(jid, tx) => {
                self.entities.insert(jid, tx);
            }
            ManagementCommand::Unregister(jid) => {
                self.entities.remove(&jid);
            }
        }
    }
}

#[derive(Clone)]
pub struct RouterHandle {
    pub stanzas: mpsc::Sender<Stanza>,
    pub management: mpsc::Sender<ManagementCommand>,
}

impl RouterHandle {
    pub fn new() -> Self {
        let (stanzas_tx, stanzas_rx) = mpsc::channel(8);
        let (management_tx, management_rx) = mpsc::channel(8);
        let mut router = Router {
            stanzas: stanzas_rx,
            management: management_rx,
            entities: HashMap::new(),
        };
        tokio::spawn(async move {
            router.run().await;
        });

        RouterHandle {
            stanzas: stanzas_tx,
            management: management_tx,
        }
    }

    pub async fn send_stanza(&mut self, stanza: Stanza) {
        self.stanzas.send(stanza).await.unwrap();
    }
}
