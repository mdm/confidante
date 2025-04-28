use std::{fmt::Display, str::FromStr};

use anyhow::Error;
use argon2::{
    password_hash::{self, rand_core::OsRng, PasswordHashString, PasswordHasher, SaltString},
    Argon2,
};

use super::StoredPassword;

#[derive(Debug)]
pub struct StoredPasswordArgon2 {
    pub hash: PasswordHashString,
}

impl StoredPassword for StoredPasswordArgon2 {
    fn new(plaintext: &str) -> Result<Self, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(plaintext.as_bytes(), &salt)?.into();
        Ok(Self { hash })
    }
}

impl FromStr for StoredPasswordArgon2 {
    type Err = password_hash::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hash = PasswordHashString::new(s)?;
        Ok(Self { hash })
    }
}

impl Display for StoredPasswordArgon2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hash)
    }
}
