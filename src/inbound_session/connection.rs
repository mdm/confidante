use tokio::net::TcpStream;

pub enum Security {
    None,
    BasicTls,
    AuthenticatedTls,
}

enum InitiatorType {
    Unknown,
    Client,
    Server,
}

pub struct Connection {
    socket: TcpStream,
    initiator_type: InitiatorType,
    security: Security,
}

impl Connection {
    pub fn from_socket(socket: TcpStream) -> Self {
        Self {
            socket,
            initiator_type: InitiatorType::Unknown,
            security: Security::None,
        }
    }

    pub fn socket(&mut self) -> &mut TcpStream {
        &mut self.socket
    }

    pub fn is_client_connection(&self) -> bool {
        match self.initiator_type {
            InitiatorType::Client => true,
            _ => false,
        }
    }

    pub fn is_server_connection(&self) -> bool {
        match self.initiator_type {
            InitiatorType::Server => true,
            _ => false,
        }
    }

    pub fn set_client_connection(&mut self) {
        self.initiator_type = InitiatorType::Client;
    }

    pub fn set_server_connection(&mut self) {
        self.initiator_type = InitiatorType::Server;
    }

    pub fn security(&self) -> &Security {
        &self.security
    }
}