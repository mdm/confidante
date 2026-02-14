use std::{io::Cursor, sync::Arc};

use anyhow::{Error, anyhow};
use rsasl::{
    callback::SessionCallback,
    config::SASLConfig,
    prelude::{Mechname, MessageSent, SASLServer, State, Validation},
};
use tokio::sync::{mpsc, oneshot};

use crate::sasl::{MechanismNegotiatorResult, StoredPassword};

#[derive(Debug)]
pub enum AuthError {
    AuthzBad,
    PasswordIncorrect,
    NoSuchUser,
}

pub struct SaslValidation;

impl Validation for SaslValidation {
    type Value = Result<String, AuthError>;
}

pub trait SessionCallbackExt {
    fn lookup_stored_password<P>(
        &self,
        authid: &str,
        tx: mpsc::Sender<(String, oneshot::Sender<Result<P, Error>>)>,
    ) -> Result<P, Error>
    where
        P: StoredPassword,
    {
        let (response_tx, response_rx) = oneshot::channel();
        tx.blocking_send((authid.to_string(), response_tx))
            .map_err(|_| anyhow!("Could not lookup stored password"))?;
        let stored_password = response_rx
            .blocking_recv()
            .map_err(|_| anyhow!("Could not lookup stored password"))?;
        stored_password.map_err(|_| anyhow!("Could not lookup stored password"))
    }
}

impl<T> SessionCallbackExt for T where T: SessionCallback {}

pub fn authenticate(
    config: Arc<SASLConfig>,
    mechname: &Mechname,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    output_tx: mpsc::Sender<MechanismNegotiatorResult>,
) -> Result<String, Error> {
    let server = SASLServer::<SaslValidation>::new(config);

    let mut server_session = server.start_suggested(mechname)?;

    while {
        let mut server_out = Cursor::new(Vec::new());
        let state = if server_session.are_we_first() {
            server_session.step(None, &mut server_out)
        } else {
            let input = input_rx
                .blocking_recv()
                .ok_or(anyhow!("Failed to receive SASL input"))?;
            server_session.step(Some(input.as_slice()), &mut server_out)
        };
        let running = state.as_ref().is_ok_and(|s| s.is_running());

        let output = match state {
            Ok(State::Running) => MechanismNegotiatorResult::Challenge(server_out.into_inner()),
            Ok(State::Finished(message_sent)) => {
                // TODO: do AuthError validations use this arm? If yes, return Failure here
                let additional_data = match message_sent {
                    MessageSent::Yes => Some(server_out.into_inner()),
                    MessageSent::No => None,
                };
                MechanismNegotiatorResult::Success(additional_data)
            }
            Err(err) => MechanismNegotiatorResult::Failure(anyhow!(err)),
        };

        output_tx
            .blocking_send(output)
            .map_err(|_| anyhow!("Failed to send SASL output"))?;

        running
    } {}

    server_session
        .validation()
        .map(|validation| validation.map_err(|err| anyhow!("Authentication failed: {:?}", err)))
        .unwrap_or(Err(anyhow!("Could not complete authentication")))
}
