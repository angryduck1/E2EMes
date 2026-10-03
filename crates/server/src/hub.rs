//! Registry of online users and their open connections, used to push events.

use std::{collections::HashMap, sync::Mutex};

use e2emes_proto::ServerFrame;
use tokio::sync::mpsc;
use tracing::debug;

pub type ConnId = u64;

#[derive(Default)]
pub struct Hub {
    users: Mutex<HashMap<i64, HashMap<ConnId, mpsc::Sender<ServerFrame>>>>,
}

impl Hub {
    /// Returns true if the user just came online (this is their first connection).
    pub fn attach(&self, user_id: i64, conn: ConnId, tx: mpsc::Sender<ServerFrame>) -> bool {
        let mut users = self.users.lock().unwrap();
        let conns = users.entry(user_id).or_default();
        conns.insert(conn, tx);
        conns.len() == 1
    }

    /// Returns true if the user just went offline (this was their last connection).
    pub fn detach(&self, user_id: i64, conn: ConnId) -> bool {
        let mut users = self.users.lock().unwrap();
        let Some(conns) = users.get_mut(&user_id) else {
            return false;
        };
        conns.remove(&conn);
        if conns.is_empty() {
            users.remove(&user_id);
            true
        } else {
            false
        }
    }

    pub fn is_online(&self, user_id: i64) -> bool {
        self.users.lock().unwrap().contains_key(&user_id)
    }

    /// Queues `frame` on every connection of `user_id` except `except`.
    ///
    /// A connection whose queue is full is skipped: the client catches up with `Sync`.
    pub fn send(&self, user_id: i64, frame: &ServerFrame, except: Option<ConnId>) {
        let users = self.users.lock().unwrap();
        let Some(conns) = users.get(&user_id) else {
            return;
        };
        for (&conn, tx) in conns {
            if Some(conn) != except && tx.try_send(frame.clone()).is_err() {
                debug!("dropping event for user {user_id} connection {conn}: queue full or closed");
            }
        }
    }
}
