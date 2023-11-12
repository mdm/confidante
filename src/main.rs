mod inbound_session;
mod jid;
mod settings;
mod types;
mod xml;

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

        // TODO: handle shutdown

        tokio::spawn(async move {
            let mut session = InboundSession::from_socket(socket, settings);

            if let Err(err) = session.handle().await {
                session.handle_unrecoverable_error(err).await;
            }

            session.close_stream().await;
        });
    }

    Ok(())
}
