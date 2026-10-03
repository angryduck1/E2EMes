//! E2EMes server: accepts Noise-encrypted connections, keeps accounts, chats and
//! end-to-end encrypted messages in SQLite, and pushes events to online users.
//!
//! The server never sees message plaintext or identity secrets; it stores
//! ciphertexts and public keys only.

mod auth;
mod conn;
mod db;
mod hub;

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use tokio::{net::TcpListener, sync::Semaphore};
use tracing::{info, warn};

pub use db::Db;

/// Upper bound on simultaneous connections.
const MAX_CONNECTIONS: usize = 4096;
/// At most this many Argon2 computations run at once (each takes ~19 MiB).
const MAX_PARALLEL_KDF: usize = 4;

pub struct Config {
    /// Path of the SQLite database, or `:memory:`.
    pub db_path: String,
    /// The server's static Noise private key.
    pub private_key: [u8; 32],
}

pub(crate) struct Shared {
    pub db: Db,
    pub hub: hub::Hub,
    pub limiter: auth::LoginLimiter,
    pub kdf: Semaphore,
    pub private_key: [u8; 32],
}

pub async fn serve(listener: TcpListener, config: Config) -> anyhow::Result<()> {
    let db = Db::open(&config.db_path).with_context(|| format!("opening database {}", config.db_path))?;
    let shared = Arc::new(Shared {
        db,
        hub: hub::Hub::default(),
        limiter: auth::LoginLimiter::new(10, Duration::from_secs(15 * 60)),
        kdf: Semaphore::new(MAX_PARALLEL_KDF),
        private_key: config.private_key,
    });

    let cleanup = shared.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            if let Err(e) = cleanup.db.call(|c| db::delete_expired_sessions(c, db::now())).await {
                warn!("session cleanup failed: {e:#}");
            }
            cleanup.limiter.forget_stale();
        }
    });

    info!("listening on {}", listener.local_addr()?);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            warn!("connection limit reached, dropping {peer}");
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            conn::handle(stream, peer, shared).await;
            drop(permit);
        });
    }
}
