mod client_session;
mod xml_stream_codec;

use client_session::ClientSession;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:5222").await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut session = ClientSession::from_socket(socket);
            session.handle().await;
        });
    }

    Ok(())
}
