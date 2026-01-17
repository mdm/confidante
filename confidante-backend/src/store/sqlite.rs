use anyhow::Error;
use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};

use confidante_core::xmpp::jid::Jid;

use crate::settings::Settings;
use crate::store::StoredPasswordKind;

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
        let bare_jid = jid.to_bare().to_string();
        sqlx::query!(
                r#"
                INSERT INTO users (bare_jid, stored_password_argon2, stored_password_scram_sha1, stored_password_scram_sha256)
                VALUES (?, ?, ?, ?)
                "#,
                bare_jid,
                stored_password_argon2,
                stored_password_scram_sha1,
                stored_password_scram_sha256,
            )
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn remove_user(&mut self, jid: Jid) -> Result<(), Error> {
        let bare_jid = jid.to_bare().to_string();
        sqlx::query!(
            r#"
                DELETE FROM users
                WHERE bare_jid = ?
                "#,
            bare_jid,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_stored_password(
        &self,
        jid: Jid,
        kind: StoredPasswordKind,
    ) -> Result<String, Error> {
        let bare_jid = jid.to_bare().to_string();
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT stored_password_argon2, stored_password_scram_sha1, stored_password_scram_sha256
            FROM users
            WHERE bare_jid = ?
            "#,
            bare_jid,
        )
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
        let bare_jid = jid.to_bare().to_string();
        match kind {
            StoredPasswordKind::Argon2 => {
                sqlx::query!(
                    r#"
                UPDATE users
                SET stored_password_argon2 = ?
                WHERE bare_jid = ?
                "#,
                    stored_password,
                    bare_jid
                )
                .execute(&self.pool)
                .await?;
            }
            StoredPasswordKind::ScramSha1 => {
                sqlx::query!(
                    r#"
                UPDATE users
                SET stored_password_scram_sha1 = ?
                WHERE bare_jid = ?
                "#,
                    stored_password,
                    bare_jid
                )
                .execute(&self.pool)
                .await?;
            }
            StoredPasswordKind::ScramSha256 => {
                sqlx::query!(
                    r#"
                UPDATE users
                SET stored_password_scram_sha256 = ?
                WHERE bare_jid = ?
                "#,
                    stored_password,
                    bare_jid
                )
                .execute(&self.pool)
                .await?;
            }
        };

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct User {
    stored_password_argon2: String,
    stored_password_scram_sha1: String,
    stored_password_scram_sha256: String,
}
