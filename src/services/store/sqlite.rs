use anyhow::Error;
use sqlx::{migrate, sqlite::SqlitePoolOptions, Pool, Sqlite};

use crate::inbound::StoredPasswordKind;
use crate::settings::Settings;
use crate::xmpp::jid::Jid;

use super::StoreBackend;

pub struct SqliteStoreBackend {
    pool: Pool<Sqlite>,
}

impl SqliteStoreBackend {
    pub async fn new(settings: &Settings) -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&settings.database_url)
            .await?;

        Ok(Self { pool })
    }
}

impl StoreBackend for SqliteStoreBackend {
    async fn add_user(
        &mut self,
        jid: Jid,
        stored_password_argon2: String,
        stored_password_scram_sha1: String,
        stored_password_scram_sha256: String,
    ) -> Result<(), Error> {
        sqlx::query(
                r#"
                INSERT INTO users (bare_jid, stored_password_argon2, stored_password_scram_sha1, stored_password_scram_sha256)
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(jid.to_bare().to_string())
            .bind(stored_password_argon2)
            .bind(stored_password_scram_sha1)
            .bind(stored_password_scram_sha256)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn remove_user(&mut self, jid: Jid) -> Result<(), Error> {
        sqlx::query(
            r#"
                DELETE FROM users
                WHERE bare_jid = ?
                "#,
        )
        .bind(jid.to_bare().to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_stored_password(
        &self,
        jid: Jid,
        kind: StoredPasswordKind,
    ) -> Result<String, Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT bare_jid, stored_password_argon2, stored_password_scram_sha1, stored_password_scram_sha256
            FROM users
            WHERE bare_jid = ?
            "#,
        )
        .bind(jid.to_bare().to_string())
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
                WHERE bare_jid = ?
                "#
            }
            StoredPasswordKind::ScramSha1 => {
                r#"
                UPDATE users
                SET stored_password_scram_sha1 = ?
                WHERE bare_jid = ?
                "#
            }
            StoredPasswordKind::ScramSha256 => {
                r#"
                UPDATE users
                SET stored_password_scram_sha256 = ?
                WHERE bare_jid = ?
                "#
            }
        };

        sqlx::query(query)
            .bind(stored_password)
            .bind(jid.to_bare().to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct User {
    bare_jid: String,
    stored_password_argon2: String,
    stored_password_scram_sha1: String,
    stored_password_scram_sha256: String,
}
