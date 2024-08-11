CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    bare_jid VARCHAR(255) NOT NULL,
    stored_password_argon2 VARCHAR(255) NOT NULL,
    stored_password_scram_sha1 VARCHAR(255) NOT NULL,
    stored_password_scram_sha256 VARCHAR(255) NOT NULL,
)
