use anyhow::Error;

use super::sasl::AuthenticatedEntity;
use super::session::Session;

pub struct BoundResource(pub String, ());


pub struct ResourceBindingNegotiator {
    _private: (),
}

impl ResourceBindingNegotiator {
    pub fn new() -> Self {
        Self {
            _private: (),
        }
    }

    pub fn bind_resource(&self, entity: AuthenticatedEntity, session: &mut Session) -> Result<BoundResource, Error> {
        todo!()
    }
}