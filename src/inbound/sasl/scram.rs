use bytes::{BufMut, BytesMut};
use digest::{generic_array::GenericArray, Digest, Output};
use rsasl::{
    callback::{Context, Request, SessionCallback, SessionData},
    config::SASLConfig,
    mechanisms::{
        self,
        scram::{self, properties::ScramStoredPassword},
    },
    mechname::Mechname,
    prelude::{SASLServer, SessionError, State},
    property::{AuthId, Password},
    validate::{Validate, Validation, ValidationError},
};
use sha1::Sha1;


pub struct ScramSha1Negotiator {

}

impl MechanismNegotiator for ScramSha1Negotiator {
    fn new() -> Self {
        Self {}
    }

    fn process(&self, payload: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        todo!();

        let plain_password = b"password";
        let salt = b"bad salt";
        let mut salted_password = GenericArray::default();
        // Derive the PBKDF2 key from the password and salt. This is the expensive part
        // TODO: do we need to off-load this to a separate thread? benchmark!
        scram::tools::hash_password::<Sha1>(plain_password, 4096, &salt[..], &mut salted_password);
        let (client_key, server_key) = scram::tools::derive_keys::<Sha1>(salted_password.as_slice());
        let stored_key = Sha1::digest(&client_key);
        
        let sasl_config = SASLConfig::builder()
            .with_defaults()
            .with_callback(SaslCallback { salt, server_key, stored_key })?;
        
        let sasl = SASLServer::<SaslValidation>::new(sasl_config);
        
        let mut sasl_session = match mechanism {
            Mechanism::ScramSha1 => sasl
                .start_suggested(Mechname::parse(b"SCRAM-SHA-1").unwrap())?,
            _ => todo!(),
        };
        
        let mut client_response = base64::decode(fragment.content_str())?;
        let mut server_challenge_or_success = BytesMut::new();
        
        let mut do_last_step = false;
        let mut done = false;
        loop {
            {
                let mut out = Cursor::new(Vec::new());
                let step_result = if do_last_step {
                    do_last_step = false;
                    sasl_session
                    .step(None, &mut out)?
                } else { 
                    sasl_session
                    .step(Some(&client_response), &mut out)?
                };
        
                match step_result {
                    (State::Running, Some(len)) => {
                        let mut challenge = BytesMut::new();
                        challenge
                            .put("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes());
                        let encoded = base64::encode(&out.into_inner()[..len]);
                        challenge.put(encoded.as_bytes());
                        challenge.put("</challenge>".as_bytes());
                        server_challenge_or_success = challenge;
                    }
                    (State::Running, None) => {
                        do_last_step = true;
                    }
                    (State::Finished, Some(len)) => {
                        // TODO: Compare identity to stream header
        
                        let mut success = BytesMut::new();
                        success
                            .put("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".as_bytes());
                        let encoded = base64::encode(&out.into_inner()[..len]);
                        success.put(encoded.as_bytes());
                        success.put("</success>".as_bytes());
                        server_challenge_or_success = success;
                        done = true;
                    }
                    (State::Finished, None) => {
                        // TODO: Compare identity to stream header
        
                        let mut success = BytesMut::new();
                        success
                            .put("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl' />".as_bytes());
                        server_challenge_or_success = success;
                        done = true;
                    }
                }
            }
        
            // dbg!(&server_challenge_or_success);
        
            session
                .write_buffer(&mut server_challenge_or_success)
                .await?;
        
            if done {
                break;
            }
        
            let fragment = match session.read_frame().await? {
                Some(XmlFrame::XmlFragment(fragment)) => fragment,
                _ => bail!("expected xml fragment"),
            };
            if fragment.name != "response" {
                bail!("expected response tag");
            }
        
            client_response = base64::decode(fragment.content_str())?;
        }
        
        match sasl_session.validation() {
            Some(Ok(entity)) => Ok(AuthenticatedEntity(entity, ())),
            _ => Err(anyhow!("validation failed")),
        }        
    }
}


struct SaslValidation;
impl Validation for SaslValidation {
    type Value = Result<String, Error>;
}

struct SaslCallback {
    stored_key: Output<Sha1>,
    server_key: Output<Sha1>,
    salt: &'static [u8],
}

impl SessionCallback for SaslCallback {
    fn callback(
        &self,
        _session_data: &SessionData,
        _context: &Context,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        request.satisfy::<ScramStoredPassword>(&ScramStoredPassword {
            iterations: 4096,
            salt: self.salt,
            stored_key: self.stored_key.as_slice(),
            server_key: self.server_key.as_slice(),
        })?;
        request.satisfy::<Password>(b"password")?;

        Ok(())
    }

    fn validate(
        &self,
        _session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        let authid = context.get_ref::<AuthId>();

        validate.with::<SaslValidation, _>(|| match authid {
            Some(user @ "user") => Ok(Ok(String::from(user))),
            _ => Ok(Err(anyhow!("Unknown user"))),
        })?;

        Ok(())
    }
}
