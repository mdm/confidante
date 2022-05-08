mod inbound_session;
mod settings;
mod xml_stream_parser;

use inbound_session::InboundSession;
use settings::Settings;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let settings = Settings::new()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5222").await?;

    loop {
        let (socket, _) = listener.accept().await?;
        let settings = settings.clone();

        tokio::spawn(async move {
            let mut session = InboundSession::from_socket(socket, settings);
            session.handle().await;
        });
    }

    Ok(())
}
