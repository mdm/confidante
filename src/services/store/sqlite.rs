use anyhow::Error;
use sqlx::{migrate, sqlite::SqlitePoolOptions, Pool, Sqlite};

use crate::inbound::StoredPasswordKind;
use crate::settings::get_settings;
use crate::xmpp::jid::Jid;

use super::StoreBackend;

pub struct SqliteStoreBackend {
    pool: Pool<Sqlite>,
}

impl SqliteStoreBackend {
    pub async fn new() -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&get_settings().database_url)
            .await?;

        Ok(Self { pool })
    }
}

impl StoreBackend for SqliteStoreBackend {
    async fn get_stored_password(
        &self,
        jid: Jid,
        kind: StoredPasswordKind,
    ) -> Result<String, Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT jid, stored_password_argon2, stored_password_scram_sha1, stored_password_scram_sha256
            FROM users
            WHERE jid = ?
            "#,
        )
        .bind(jid.to_string())
        .fetch_one(&self.pool)
        .await?;

        match kind {
            StoredPasswordKind::Argon2 => Ok(user.stored_password_argon2),
            StoredPasswordKind::ScramSha1 => Ok(user.stored_password_scram_sha1),
            StoredPasswordKind::ScramSha256 => Ok(user.stored_password_scram_sha256),
        }
    }

    async fn set_stored_password(
        &mut self,
        jid: Jid,
        kind: StoredPasswordKind,
        stored_password: String,
    ) -> Result<(), Error> {
        let query = match kind {
            StoredPasswordKind::Argon2 => {
                r#"
                UPDATE users
                SET stored_password_argon2 = ?
                WHERE jid = ?
                "#
            }
            StoredPasswordKind::ScramSha1 => {
                r#"
                UPDATE users
                SET stored_password_scram_sha1 = ?
                WHERE jid = ?
                "#
            }
            StoredPasswordKind::ScramSha256 => {
                r#"
                UPDATE users
                SET stored_password_scram_sha256 = ?
                WHERE jid = ?
                "#
            }
        };

        sqlx::query(query)
            .bind(stored_password)
            .bind(jid.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct User {
    jid: String,
    stored_password_argon2: String,
    stored_password_scram_sha1: String,
    stored_password_scram_sha256: String,
}
