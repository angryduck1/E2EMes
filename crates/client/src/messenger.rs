//! High-level client: account login, key pinning, encryption and sync.
//!
//! Peer identity keys are pinned on first sight (trust on first use). If the server
//! later reports a different key for a peer, sending to and reading from that peer
//! stop until the user compares safety numbers and accepts the new key with
//! [`Messenger::accept_changed_key`].

use e2emes_crypto::{safety_number, Identity};
use e2emes_proto::{
    ChatList, ErrorCode, Event, PublicKey, Request, Response, StoredMessage, UserInfo, MAX_SYNC_LIMIT, MAX_TEXT_LEN,
};
use zeroize::Zeroizing;

use crate::{
    connection::{Connection, RequestError},
    store::{Peer, Store},
};

#[derive(Debug, thiserror::Error)]
pub enum MessengerError {
    #[error(transparent)]
    Request(#[from] RequestError),
    #[error(
        "the server reports a NEW identity key for {0}. Someone may be intercepting the chat. \
         Compare safety numbers with them in person, then run /trust {0}"
    )]
    KeyChanged(String),
    #[error("the recovery phrase does not belong to this account")]
    WrongPhrase,
    #[error("{0}")]
    Other(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl MessengerError {
    pub fn api_code(&self) -> Option<ErrorCode> {
        match self {
            MessengerError::Request(RequestError::Api(e)) => Some(e.code),
            _ => None,
        }
    }
}

type Result<T> = std::result::Result<T, MessengerError>;

fn unexpected(response: Response) -> MessengerError {
    MessengerError::Other(format!("unexpected server response: {response:?}"))
}

/// A message after decryption. `text` is `Err` with a reason if it can't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    pub id: i64,
    pub from: String,
    pub to: String,
    pub timestamp: i64,
    pub text: std::result::Result<String, String>,
}

/// Something the UI should show after an event from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Message(Decrypted),
    ChatRequest {
        name: String,
    },
    ChatAccepted {
        name: String,
    },
    Presence {
        name: String,
        online: bool,
    },
    /// The event needs no output (e.g. a duplicate message).
    Nothing,
}

pub struct Messenger {
    conn: Connection,
    store: Store,
    identity: Identity,
    me: String,
}

impl Messenger {
    /// Creates a new account with a fresh identity. Returns the session token and
    /// the recovery phrase, which the user must write down.
    pub async fn register(
        conn: Connection,
        store: Store,
        name: &str,
        password: &str,
    ) -> Result<(Self, String, Zeroizing<String>)> {
        let (identity, phrase) = Identity::generate();
        let response = conn
            .request(Request::Register {
                name: name.to_owned(),
                password: password.to_owned(),
                identity_key: PublicKey(identity.public_key()),
            })
            .await?;
        let Response::Authenticated { name, token, .. } = response else {
            return Err(unexpected(response));
        };
        Ok((
            Self {
                conn,
                store,
                identity,
                me: name,
            },
            token,
            phrase,
        ))
    }

    /// Logs in with a password on a device that knows the recovery phrase.
    pub async fn login(
        conn: Connection,
        store: Store,
        name: &str,
        password: &str,
        phrase: &str,
    ) -> Result<(Self, String)> {
        let identity = Identity::from_phrase(phrase).map_err(|e| MessengerError::Other(e.to_string()))?;
        let response = conn
            .request(Request::Login {
                name: name.to_owned(),
                password: password.to_owned(),
            })
            .await?;
        Self::finish_auth(conn, store, identity, response).await
    }

    /// Logs in with a saved session token.
    pub async fn resume(conn: Connection, store: Store, token: &str, phrase: &str) -> Result<(Self, String)> {
        let identity = Identity::from_phrase(phrase).map_err(|e| MessengerError::Other(e.to_string()))?;
        let response = conn
            .request(Request::Resume {
                token: token.to_owned(),
            })
            .await?;
        Self::finish_auth(conn, store, identity, response).await
    }

    async fn finish_auth(
        conn: Connection,
        store: Store,
        identity: Identity,
        response: Response,
    ) -> Result<(Self, String)> {
        let Response::Authenticated {
            name,
            token,
            identity_key,
        } = response
        else {
            return Err(unexpected(response));
        };
        if identity_key.0 != identity.public_key() {
            let _ = conn.request(Request::Logout).await;
            return Err(MessengerError::WrongPhrase);
        }
        Ok((
            Self {
                conn,
                store,
                identity,
                me: name,
            },
            token,
        ))
    }

    pub fn name(&self) -> &str {
        &self.me
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    pub async fn ping(&self) -> Result<()> {
        self.conn.request(Request::Ping).await?;
        Ok(())
    }

    /// Revokes the session token on the server.
    pub async fn logout(&self) -> Result<()> {
        self.conn.request(Request::Logout).await?;
        Ok(())
    }

    /// Pins the key on first sight; flags a mismatch with the pinned key.
    fn check_key(&self, info: &UserInfo) -> Result<()> {
        match self.store.peer(&info.name)? {
            None => self.store.pin_peer(&info.name, &info.identity_key.0)?,
            Some(peer) if peer.identity_key == info.identity_key.0 => {}
            Some(peer) => {
                if peer.changed_key != Some(info.identity_key.0) {
                    self.store.mark_key_changed(&peer.name, &info.identity_key.0)?;
                }
                return Err(MessengerError::KeyChanged(peer.name));
            }
        }
        Ok(())
    }

    /// Looks up a user on the server and pins their key if new.
    async fn fetch_peer(&self, name: &str) -> Result<Peer> {
        let response = self.conn.request(Request::LookupUser { name: name.to_owned() }).await?;
        let Response::User(info) = response else {
            return Err(unexpected(response));
        };
        self.check_key(&info)?;
        Ok(self.store.peer(&info.name)?.expect("just pinned"))
    }

    fn trusted_peer(&self, name: &str) -> Result<Option<Peer>> {
        match self.store.peer(name)? {
            Some(peer) if peer.changed_key.is_some() => Err(MessengerError::KeyChanged(peer.name)),
            other => Ok(other),
        }
    }

    /// Asks `name` for a chat. Returns whether the chat is already open.
    pub async fn request_chat(&self, name: &str) -> Result<(String, bool)> {
        let response = self
            .conn
            .request(Request::RequestChat { name: name.to_owned() })
            .await?;
        let Response::ChatStatus { user, open } = response else {
            return Err(unexpected(response));
        };
        self.check_key(&user)?;
        Ok((user.name, open))
    }

    pub async fn respond_chat(&self, name: &str, accept: bool) -> Result<String> {
        let response = self
            .conn
            .request(Request::RespondChat {
                name: name.to_owned(),
                accept,
            })
            .await?;
        let Response::ChatStatus { user, .. } = response else {
            return Err(unexpected(response));
        };
        if accept {
            self.check_key(&user)?;
        }
        Ok(user.name)
    }

    /// Lists chats and requests. Keys of open chats are checked against pinned ones;
    /// a mismatch is recorded and shown by [`Messenger::peer`].
    pub async fn chats(&self) -> Result<ChatList> {
        let response = self.conn.request(Request::ListChats).await?;
        let Response::Chats(list) = response else {
            return Err(unexpected(response));
        };
        for chat in &list.chats {
            match self.check_key(chat) {
                Ok(()) | Err(MessengerError::KeyChanged(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(list)
    }

    pub fn peer(&self, name: &str) -> Result<Option<Peer>> {
        Ok(self.store.peer(name)?)
    }

    pub async fn send(&self, name: &str, text: &str) -> Result<Decrypted> {
        if text.is_empty() {
            return Err(MessengerError::Other("empty message".into()));
        }
        if text.len() > MAX_TEXT_LEN {
            return Err(MessengerError::Other(format!(
                "message is longer than {MAX_TEXT_LEN} bytes"
            )));
        }
        let peer = match self.trusted_peer(name)? {
            Some(peer) => peer,
            None => self.fetch_peer(name).await?,
        };
        let key = self
            .identity
            .chat_key(&peer.identity_key)
            .map_err(|e| MessengerError::Other(e.to_string()))?;
        let (nonce, ciphertext) = key.encrypt(&self.me, &peer.name, text.as_bytes());

        let response = self
            .conn
            .request(Request::SendMessage {
                to: peer.name.clone(),
                nonce: nonce.clone(),
                ciphertext: ciphertext.clone(),
            })
            .await?;
        let Response::MessageAccepted { id, timestamp } = response else {
            return Err(unexpected(response));
        };
        self.store.insert_message(&StoredMessage {
            id,
            from: self.me.clone(),
            to: peer.name.clone(),
            timestamp,
            nonce,
            ciphertext,
        })?;
        Ok(Decrypted {
            id,
            from: self.me.clone(),
            to: peer.name,
            timestamp,
            text: Ok(text.to_owned()),
        })
    }

    fn partner<'a>(&self, m: &'a StoredMessage) -> &'a str {
        if m.from.eq_ignore_ascii_case(&self.me) {
            &m.to
        } else {
            &m.from
        }
    }

    pub fn decrypt(&self, m: &StoredMessage) -> Decrypted {
        let text = (|| {
            let peer = self
                .store
                .peer(self.partner(m))
                .map_err(|e| e.to_string())?
                .ok_or("unknown sender key")?;
            if peer.changed_key.is_some() {
                return Err(format!(
                    "identity key of {} changed, run /trust {}",
                    peer.name, peer.name
                ));
            }
            let key = self.identity.chat_key(&peer.identity_key).map_err(|e| e.to_string())?;
            let plain = key
                .decrypt(&m.from, &m.to, &m.nonce, &m.ciphertext)
                .map_err(|_| "can't decrypt: wrong key or tampered message".to_string())?;
            String::from_utf8(plain).map_err(|_| "message is not valid UTF-8".to_string())
        })();
        Decrypted {
            id: m.id,
            from: m.from.clone(),
            to: m.to.clone(),
            timestamp: m.timestamp,
            text,
        }
    }

    /// Makes sure we have a pinned key for the other side of `m`.
    async fn ensure_peer_for(&self, m: &StoredMessage) -> Result<()> {
        let partner = self.partner(m).to_owned();
        if self.store.peer(&partner)?.is_none() {
            match self.fetch_peer(&partner).await {
                Ok(_) | Err(MessengerError::KeyChanged(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Downloads every message newer than the local history; returns them decrypted.
    pub async fn sync(&self) -> Result<Vec<Decrypted>> {
        let mut new = Vec::new();
        loop {
            let after_id = self.store.last_message_id()?;
            let response = self
                .conn
                .request(Request::Sync {
                    after_id,
                    limit: MAX_SYNC_LIMIT,
                })
                .await?;
            let Response::Messages { messages, more } = response else {
                return Err(unexpected(response));
            };
            for m in &messages {
                self.ensure_peer_for(m).await?;
                if self.store.insert_message(m)? {
                    new.push(self.decrypt(m));
                }
            }
            if !more || messages.is_empty() {
                return Ok(new);
            }
        }
    }

    pub fn history(&self, name: &str, limit: u32) -> Result<Vec<Decrypted>> {
        Ok(self
            .store
            .history(name, limit)?
            .iter()
            .map(|m| self.decrypt(m))
            .collect())
    }

    pub fn safety_number(&self, name: &str) -> Result<Option<String>> {
        Ok(self.store.peer(name)?.map(|peer| {
            safety_number(
                &self.identity.public_key(),
                &peer.changed_key.unwrap_or(peer.identity_key),
            )
        }))
    }

    pub fn mark_verified(&self, name: &str) -> Result<()> {
        if self.trusted_peer(name)?.is_none() {
            return Err(MessengerError::Other(format!("no key known for {name}")));
        }
        Ok(self.store.set_verified(name)?)
    }

    /// Accepts the new key the server reported for `name`.
    pub fn accept_changed_key(&self, name: &str) -> Result<bool> {
        Ok(self.store.accept_changed_key(name)?)
    }

    pub async fn handle_event(&self, event: Event) -> Result<Notice> {
        Ok(match event {
            Event::NewMessage(m) => {
                self.ensure_peer_for(&m).await?;
                if self.store.insert_message(&m)? {
                    Notice::Message(self.decrypt(&m))
                } else {
                    Notice::Nothing
                }
            }
            Event::ChatRequest(user) => Notice::ChatRequest { name: user.name },
            Event::ChatAccepted(user) => {
                let name = user.name.clone();
                self.check_key(&user)?;
                Notice::ChatAccepted { name }
            }
            Event::Presence { name, online } => Notice::Presence { name, online },
        })
    }
}
