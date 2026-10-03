//! SQLite storage. All queries are synchronous and run on the blocking pool via [`Db::call`].

use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use e2emes_proto::{PublicKey, StoredMessage};
use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    identity_key  BLOB    NOT NULL,
    created_at    INTEGER NOT NULL
);

-- Only a SHA-256 of each token is stored, so a database leak doesn't hand out sessions.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_requests (
    from_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (from_id, to_id)
);

CREATE TABLE IF NOT EXISTS chats (
    user_a     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_a, user_b),
    CHECK (user_a < user_b)
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    nonce        BLOB    NOT NULL,
    ciphertext   BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_by_recipient ON messages(recipient_id, id);
CREATE INDEX IF NOT EXISTS messages_by_sender    ON messages(sender_id, id);
"#;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        if path != ":memory:" {
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `f` with exclusive access to the connection on the blocking thread pool.
    pub async fn call<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Connection) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            f(&mut guard)
        })
        .await?
    }
}

#[derive(Clone)]
pub struct UserRow {
    pub id: i64,
    pub name: String,
    pub password_hash: String,
    pub identity_key: PublicKey,
}

fn key_from_blob(blob: Vec<u8>) -> rusqlite::Result<PublicKey> {
    let bytes: [u8; 32] = blob
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidColumnType(0, "identity_key".into(), rusqlite::types::Type::Blob))?;
    Ok(PublicKey(bytes))
}

fn user_from_row(row: &rusqlite::Row) -> rusqlite::Result<UserRow> {
    Ok(UserRow {
        id: row.get(0)?,
        name: row.get(1)?,
        password_hash: row.get(2)?,
        identity_key: key_from_blob(row.get(3)?)?,
    })
}

pub fn user_by_name(c: &Connection, name: &str) -> Result<Option<UserRow>> {
    Ok(c.query_row(
        "SELECT id, name, password_hash, identity_key FROM users WHERE name = ?1",
        [name],
        user_from_row,
    )
    .optional()?)
}

pub fn user_by_id(c: &Connection, id: i64) -> Result<Option<UserRow>> {
    Ok(c.query_row(
        "SELECT id, name, password_hash, identity_key FROM users WHERE id = ?1",
        [id],
        user_from_row,
    )
    .optional()?)
}

/// Returns `None` if the name is taken (names are unique case-insensitively).
pub fn insert_user(c: &Connection, name: &str, password_hash: &str, key: &PublicKey) -> Result<Option<i64>> {
    let inserted = c.execute(
        "INSERT INTO users (name, password_hash, identity_key, created_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(name) DO NOTHING",
        params![name, password_hash, key.0.as_slice(), now()],
    )?;
    Ok((inserted == 1).then(|| c.last_insert_rowid()))
}

pub fn insert_session(c: &Connection, token_hash: &[u8; 32], user_id: i64, expires_at: i64) -> Result<()> {
    c.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash.as_slice(), user_id, now(), expires_at],
    )?;
    Ok(())
}

pub fn session_user(c: &Connection, token_hash: &[u8; 32]) -> Result<Option<i64>> {
    Ok(c.query_row(
        "SELECT user_id FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
        params![token_hash.as_slice(), now()],
        |row| row.get(0),
    )
    .optional()?)
}

pub fn delete_session(c: &Connection, token_hash: &[u8; 32]) -> Result<()> {
    c.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash.as_slice()])?;
    Ok(())
}

pub fn delete_expired_sessions(c: &Connection, now: i64) -> Result<()> {
    c.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?;
    Ok(())
}

fn ordered(a: i64, b: i64) -> (i64, i64) {
    (a.min(b), a.max(b))
}

pub fn chat_exists(c: &Connection, a: i64, b: i64) -> Result<bool> {
    let (a, b) = ordered(a, b);
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM chats WHERE user_a = ?1 AND user_b = ?2)",
        [a, b],
        |row| row.get(0),
    )?)
}

pub fn insert_chat(c: &Connection, a: i64, b: i64) -> Result<()> {
    let (a, b) = ordered(a, b);
    c.execute(
        "INSERT OR IGNORE INTO chats (user_a, user_b, created_at) VALUES (?1, ?2, ?3)",
        params![a, b, now()],
    )?;
    Ok(())
}

pub fn insert_request(c: &Connection, from: i64, to: i64) -> Result<()> {
    c.execute(
        "INSERT OR IGNORE INTO chat_requests (from_id, to_id, created_at) VALUES (?1, ?2, ?3)",
        params![from, to, now()],
    )?;
    Ok(())
}

/// Returns whether a request was actually removed.
pub fn delete_request(c: &Connection, from: i64, to: i64) -> Result<bool> {
    Ok(c.execute(
        "DELETE FROM chat_requests WHERE from_id = ?1 AND to_id = ?2",
        [from, to],
    )? == 1)
}

fn users_query(c: &Connection, sql: &str, user_id: i64) -> Result<Vec<UserRow>> {
    let mut stmt = c.prepare(sql)?;
    let rows = stmt.query_map([user_id], user_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn chat_partners(c: &Connection, user_id: i64) -> Result<Vec<UserRow>> {
    users_query(
        c,
        "SELECT u.id, u.name, u.password_hash, u.identity_key FROM chats ch
         JOIN users u ON u.id = CASE WHEN ch.user_a = ?1 THEN ch.user_b ELSE ch.user_a END
         WHERE ch.user_a = ?1 OR ch.user_b = ?1
         ORDER BY u.name",
        user_id,
    )
}

pub fn incoming_requests(c: &Connection, user_id: i64) -> Result<Vec<UserRow>> {
    users_query(
        c,
        "SELECT u.id, u.name, u.password_hash, u.identity_key FROM chat_requests r
         JOIN users u ON u.id = r.from_id WHERE r.to_id = ?1 ORDER BY r.created_at",
        user_id,
    )
}

pub fn outgoing_requests(c: &Connection, user_id: i64) -> Result<Vec<UserRow>> {
    users_query(
        c,
        "SELECT u.id, u.name, u.password_hash, u.identity_key FROM chat_requests r
         JOIN users u ON u.id = r.to_id WHERE r.from_id = ?1 ORDER BY r.created_at",
        user_id,
    )
}

pub fn insert_message(c: &Connection, from: i64, to: i64, nonce: &[u8], ciphertext: &[u8]) -> Result<(i64, i64)> {
    let ts = now();
    c.execute(
        "INSERT INTO messages (sender_id, recipient_id, created_at, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![from, to, ts, nonce, ciphertext],
    )?;
    Ok((c.last_insert_rowid(), ts))
}

/// Messages sent or received by `user_id` with `id > after_id`, oldest first.
pub fn messages_after(c: &Connection, user_id: i64, after_id: i64, limit: u32) -> Result<Vec<StoredMessage>> {
    let mut stmt = c.prepare(
        "SELECT m.id, s.name, r.name, m.created_at, m.nonce, m.ciphertext FROM messages m
         JOIN users s ON s.id = m.sender_id
         JOIN users r ON r.id = m.recipient_id
         WHERE (m.sender_id = ?1 OR m.recipient_id = ?1) AND m.id > ?2
         ORDER BY m.id LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![user_id, after_id, limit], |row| {
        Ok(StoredMessage {
            id: row.get(0)?,
            from: row.get(1)?,
            to: row.get(2)?,
            timestamp: row.get(3)?,
            nonce: row.get(4)?,
            ciphertext: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_case_insensitively() {
        let db = Db::open(":memory:").unwrap();
        let c = db.conn.lock().unwrap();
        let key = PublicKey([1; 32]);
        assert!(insert_user(&c, "Alice", "h", &key).unwrap().is_some());
        assert!(insert_user(&c, "alice", "h", &key).unwrap().is_none());
        assert_eq!(user_by_name(&c, "ALICE").unwrap().unwrap().name, "Alice");
    }

    #[test]
    fn chats_are_symmetric() {
        let db = Db::open(":memory:").unwrap();
        let c = db.conn.lock().unwrap();
        let key = PublicKey([1; 32]);
        let a = insert_user(&c, "aaa", "h", &key).unwrap().unwrap();
        let b = insert_user(&c, "bbb", "h", &key).unwrap().unwrap();
        insert_chat(&c, b, a).unwrap();
        assert!(chat_exists(&c, a, b).unwrap());
        assert_eq!(chat_partners(&c, a).unwrap()[0].name, "bbb");
        assert_eq!(chat_partners(&c, b).unwrap()[0].name, "aaa");
    }
}
