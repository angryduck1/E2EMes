//! Request, response and event types exchanged over the encrypted transport.
//!
//! The client sends [`ClientFrame`]s. The server answers each one with a
//! [`ServerFrame::Response`] carrying the same `id`, and may push
//! [`ServerFrame::Event`]s at any time (new messages, chat requests, presence).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hexser;

/// An X25519 public key (identity key of a user).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "hexser::key")] pub [u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientFrame {
    pub id: u64,
    pub request: Request,
}

/// Requests sent by the client. No `Debug`: some variants carry passwords.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Create an account and log in.
    Register {
        name: String,
        password: String,
        identity_key: PublicKey,
    },
    /// Log in with a password, creating a new session token.
    Login {
        name: String,
        password: String,
    },
    /// Log in with a session token from a previous `Register`/`Login`.
    Resume {
        token: String,
    },
    /// Revoke the current session token.
    Logout,
    Ping,
    LookupUser {
        name: String,
    },
    /// Ask `name` to open a chat. If `name` already asked us, the chat opens at once.
    RequestChat {
        name: String,
    },
    /// Answer a pending chat request from `name`.
    RespondChat {
        name: String,
        accept: bool,
    },
    ListChats,
    SendMessage {
        to: String,
        #[serde(with = "hexser::bytes")]
        nonce: Vec<u8>,
        #[serde(with = "hexser::bytes")]
        ciphertext: Vec<u8>,
    },
    /// Fetch messages sent or received by the current user with `id > after_id`.
    Sync {
        after_id: i64,
        limit: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Pong,
    Authenticated {
        name: String,
        token: String,
        identity_key: PublicKey,
    },
    User(UserInfo),
    /// Result of `RequestChat`/`RespondChat`: `open` is true once both sides agreed.
    ChatStatus {
        user: UserInfo,
        open: bool,
    },
    Chats(ChatList),
    MessageAccepted {
        id: i64,
        timestamp: i64,
    },
    Messages {
        messages: Vec<StoredMessage>,
        more: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub identity_key: PublicKey,
    pub online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChatList {
    /// Open chats.
    pub chats: Vec<UserInfo>,
    /// Users waiting for our answer.
    pub incoming: Vec<UserInfo>,
    /// Users we are waiting for.
    pub outgoing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: i64,
    pub from: String,
    pub to: String,
    pub timestamp: i64,
    #[serde(with = "hexser::bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hexser::bytes")]
    pub ciphertext: Vec<u8>,
}

/// Pushed by the server without a matching request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    NewMessage(StoredMessage),
    ChatRequest(UserInfo),
    ChatAccepted(UserInfo),
    Presence { name: String, online: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum ServerFrame {
    Response {
        id: u64,
        result: Result<Response, ApiError>,
    },
    Event(Event),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    InvalidName,
    WeakPassword,
    NameTaken,
    InvalidCredentials,
    TooManyAttempts,
    Unauthorized,
    AlreadyAuthenticated,
    NotFound,
    NotAChat,
    TooLarge,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.message, self.code)
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_as_json() {
        let frame = ServerFrame::Event(Event::NewMessage(StoredMessage {
            id: 7,
            from: "alice".into(),
            to: "bob".into(),
            timestamp: 1,
            nonce: vec![1, 2],
            ciphertext: vec![0xff],
        }));
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"ciphertext\":\"ff\""), "{json}");
        let back: ServerFrame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, ServerFrame::Event(Event::NewMessage(m)) if m.id == 7));

        let frame = ServerFrame::Response {
            id: 3,
            result: Err(ApiError::new(ErrorCode::NameTaken, "taken")),
        };
        let back: ServerFrame = serde_json::from_str(&serde_json::to_string(&frame).unwrap()).unwrap();
        assert!(matches!(back, ServerFrame::Response { id: 3, result: Err(e) } if e.code == ErrorCode::NameTaken));
    }

    #[test]
    fn bad_hex_is_rejected() {
        let json = r#"{"id":1,"request":{"type":"send_message","to":"bob","nonce":"zz","ciphertext":"00"}}"#;
        assert!(serde_json::from_str::<ClientFrame>(json).is_err());
    }
}
