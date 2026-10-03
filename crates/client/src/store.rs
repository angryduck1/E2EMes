//! Local SQLite store: pinned peer keys and the (still encrypted) message history.

use std::path::Path;

use e2emes_proto::StoredMessage;
use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS peers (
    name         TEXT    PRIMARY KEY COLLATE NOCASE,
    identity_key BLOB    NOT NULL,
    verified     INTEGER NOT NULL DEFAULT 0,
    -- Set when the server reports a different key than the pinned one.
    changed_key  BLOB
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY,
    sender     TEXT    NOT NULL,
    recipient  TEXT    NOT NULL,
    timestamp  INTEGER NOT NULL,
    nonce      BLOB    NOT NULL,
    ciphertext BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_by_sender    ON messages(sender COLLATE NOCASE, id);
CREATE INDEX IF NOT EXISTS messages_by_recipient ON messages(recipient COLLATE NOCASE, id);
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    pub identity_key: [u8; 32],
    pub verified: bool,
    pub changed_key: Option<[u8; 32]>,
}

pub struct Store {
    conn: Connection,
}

fn key(blob: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    blob.try_into()
        .map_err(|_| rusqlite::Error::InvalidColumnType(0, "key".into(), rusqlite::types::Type::Blob))
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn peer(&self, name: &str) -> anyhow::Result<Option<Peer>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name, identity_key, verified, changed_key FROM peers WHERE name = ?1",
                [name],
                |row| {
                    Ok(Peer {
                        name: row.get(0)?,
                        identity_key: key(row.get(1)?)?,
                        verified: row.get(2)?,
                        changed_key: row.get::<_, Option<Vec<u8>>>(3)?.map(key).transpose()?,
                    })
                },
            )
            .optional()?)
    }

    pub fn pin_peer(&self, name: &str, identity_key: &[u8; 32]) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO peers (name, identity_key) VALUES (?1, ?2)",
            params![name, identity_key.as_slice()],
        )?;
        Ok(())
    }

    pub fn mark_key_changed(&self, name: &str, new_key: &[u8; 32]) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE peers SET changed_key = ?2 WHERE name = ?1",
            params![name, new_key.as_slice()],
        )?;
        Ok(())
    }

    /// Replaces the pinned key with the reported new one; the peer becomes unverified.
    pub fn accept_changed_key(&self, name: &str) -> anyhow::Result<bool> {
        Ok(self.conn.execute(
            "UPDATE peers SET identity_key = changed_key, changed_key = NULL, verified = 0
             WHERE name = ?1 AND changed_key IS NOT NULL",
            [name],
        )? == 1)
    }

    pub fn set_verified(&self, name: &str) -> anyhow::Result<()> {
        self.conn
            .execute("UPDATE peers SET verified = 1 WHERE name = ?1", [name])?;
        Ok(())
    }

    /// Returns false if the message was already stored.
    pub fn insert_message(&self, m: &StoredMessage) -> anyhow::Result<bool> {
        Ok(self.conn.execute(
            "INSERT OR IGNORE INTO messages (id, sender, recipient, timestamp, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![m.id, m.from, m.to, m.timestamp, m.nonce, m.ciphertext],
        )? == 1)
    }

    /// Highest server message id seen; the next `Sync` starts after it.
    pub fn last_message_id(&self) -> anyhow::Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM messages", [], |row| row.get(0))?)
    }

    /// The last `limit` messages exchanged with `peer`, oldest first.
    pub fn history(&self, peer: &str, limit: u32) -> anyhow::Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, recipient, timestamp, nonce, ciphertext FROM (
                SELECT * FROM messages
                WHERE sender = ?1 COLLATE NOCASE OR recipient = ?1 COLLATE NOCASE
                ORDER BY id DESC LIMIT ?2
             ) ORDER BY id",
        )?;
        let rows = stmt.query_map(params![peer, limit], |row| {
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
}
