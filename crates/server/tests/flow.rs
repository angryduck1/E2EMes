//! End-to-end scenarios: a real server on a random port and real clients.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use e2emes_client::{connect, Connection, Messenger, MessengerError, Notice, Store};
use e2emes_proto::{transport::StaticKeypair, ErrorCode, Event, Request, Response};
use e2emes_server::{serve, Config};
use tokio::{net::TcpListener, sync::mpsc::UnboundedReceiver, time::timeout};

const PW: &str = "correct horse battery";

struct TestServer {
    addr: String,
    public: [u8; 32],
    db_path: PathBuf,
}

fn temp_path(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "e2emes-test-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

async fn start_server() -> TestServer {
    let key = StaticKeypair::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let db_path = temp_path("server.db");
    let config = Config {
        db_path: db_path.to_string_lossy().into_owned(),
        private_key: key.private,
    };
    tokio::spawn(async move { serve(listener, config).await.unwrap() });
    TestServer {
        addr,
        public: key.public,
        db_path,
    }
}

impl TestServer {
    async fn connect(&self) -> (Connection, UnboundedReceiver<Event>) {
        connect(&self.addr, &self.public).await.unwrap()
    }

    async fn register(&self, name: &str) -> (Messenger, UnboundedReceiver<Event>, String, String) {
        let (conn, events) = self.connect().await;
        let (m, token, phrase) = Messenger::register(conn, Store::in_memory().unwrap(), name, PW)
            .await
            .unwrap();
        (m, events, token, phrase.to_string())
    }
}

async fn next_event(events: &mut UnboundedReceiver<Event>) -> Event {
    timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("event in time")
        .expect("connection open")
}

/// Skips presence notifications, which arrive whenever someone connects.
async fn next_non_presence(events: &mut UnboundedReceiver<Event>) -> Event {
    loop {
        match next_event(events).await {
            Event::Presence { .. } => continue,
            other => return other,
        }
    }
}

fn code(e: MessengerError) -> ErrorCode {
    e.api_code().unwrap_or_else(|| panic!("expected an API error, got {e}"))
}

/// alice and bob with an open chat.
async fn chat_pair(server: &TestServer) -> (Messenger, UnboundedReceiver<Event>, Messenger, UnboundedReceiver<Event>) {
    let (alice, mut alice_events, _, _) = server.register("alice").await;
    let (bob, mut bob_events, _, _) = server.register("bob").await;
    assert_eq!(alice.request_chat("bob").await.unwrap(), ("bob".into(), false));
    assert!(matches!(next_non_presence(&mut bob_events).await, Event::ChatRequest(u) if u.name == "alice"));
    bob.respond_chat("alice", true).await.unwrap();
    assert!(matches!(next_non_presence(&mut alice_events).await, Event::ChatAccepted(u) if u.name == "bob"));
    (alice, alice_events, bob, bob_events)
}

#[tokio::test]
async fn messages_are_end_to_end_encrypted_and_pushed() {
    let server = start_server().await;
    let (alice, _alice_events, bob, mut bob_events) = chat_pair(&server).await;

    let secret = "встречаемся в 7, пароль 'синий слон'";
    let sent = alice.send("bob", secret).await.unwrap();
    assert_eq!(sent.text.as_deref(), Ok(secret));

    let event = next_non_presence(&mut bob_events).await;
    let Notice::Message(received) = bob.handle_event(event).await.unwrap() else {
        panic!("expected a message");
    };
    assert_eq!(
        (received.from.as_str(), received.text.as_deref()),
        ("alice", Ok(secret))
    );

    // Already stored from the push, so sync brings nothing new; history has it.
    assert!(bob.sync().await.unwrap().is_empty());
    assert_eq!(bob.history("alice", 10).unwrap()[0].text.as_deref(), Ok(secret));

    // The server only ever had ciphertext.
    let db = std::fs::read(&server.db_path).unwrap();
    let wal = std::fs::read(server.db_path.with_extension("db-wal")).unwrap_or_default();
    for haystack in [&db, &wal] {
        assert!(!haystack.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
}

#[tokio::test]
async fn registration_rules() {
    let server = start_server().await;
    server.register("alice").await;

    for (name, password, expected) in [
        ("ALICE", PW, ErrorCode::NameTaken), // names are case-insensitive
        ("../evil", PW, ErrorCode::InvalidName),
        ("ab", PW, ErrorCode::InvalidName),
        ("charlie", "short", ErrorCode::WeakPassword),
    ] {
        let (conn, _) = server.connect().await;
        let e = Messenger::register(conn, Store::in_memory().unwrap(), name, password)
            .await
            .err()
            .unwrap();
        assert_eq!(code(e), expected, "{name}");
    }
}

#[tokio::test]
async fn chats_need_consent() {
    let server = start_server().await;
    let (_alice, _, _, _) = server.register("alice").await;
    let (bob, mut bob_events, _, _) = server.register("bob").await;
    let (mallory, _, _, _) = server.register("mallory").await;

    // Accepting a request that was never made doesn't open a chat.
    assert_eq!(
        code(mallory.respond_chat("bob", true).await.unwrap_err()),
        ErrorCode::NotFound
    );
    assert_eq!(code(mallory.send("bob", "hi").await.unwrap_err()), ErrorCode::NotAChat);

    // A declined request doesn't open one either.
    mallory.request_chat("bob").await.unwrap();
    assert!(matches!(next_non_presence(&mut bob_events).await, Event::ChatRequest(u) if u.name == "mallory"));
    bob.respond_chat("mallory", false).await.unwrap();
    assert_eq!(code(mallory.send("bob", "hi").await.unwrap_err()), ErrorCode::NotAChat);
    assert_eq!(
        code(bob.respond_chat("mallory", true).await.unwrap_err()),
        ErrorCode::NotFound
    );

    // Two requests in opposite directions open the chat.
    mallory.request_chat("alice").await.unwrap();
    assert_eq!(_alice.request_chat("mallory").await.unwrap(), ("mallory".into(), true));
    mallory.send("alice", "hi").await.unwrap();

    assert_eq!(code(bob.request_chat("bob").await.unwrap_err()), ErrorCode::BadRequest);
    assert_eq!(code(bob.request_chat("nobody").await.unwrap_err()), ErrorCode::NotFound);
}

#[tokio::test]
async fn login_resume_and_logout() {
    let server = start_server().await;
    let (_alice, _, token, phrase) = server.register("alice").await;

    // A new device restores the account with the password and the recovery phrase.
    let (conn, _) = server.connect().await;
    let (m, new_token) = Messenger::login(conn, Store::in_memory().unwrap(), "alice", PW, &phrase)
        .await
        .unwrap();
    assert_eq!(m.name(), "alice");
    assert_ne!(new_token, token);

    // The right password with someone else's phrase is refused.
    let (_, _, _, other_phrase) = server.register("bob").await;
    let (conn, _) = server.connect().await;
    let e = Messenger::login(conn, Store::in_memory().unwrap(), "alice", PW, &other_phrase)
        .await
        .err()
        .unwrap();
    assert!(matches!(e, MessengerError::WrongPhrase));

    // Saved token works, and stops working after logout.
    let (conn, _) = server.connect().await;
    let (m, _) = Messenger::resume(conn, Store::in_memory().unwrap(), &token, &phrase)
        .await
        .unwrap();
    m.logout().await.unwrap();
    let (conn, _) = server.connect().await;
    let e = Messenger::resume(conn, Store::in_memory().unwrap(), &token, &phrase)
        .await
        .err()
        .unwrap();
    assert_eq!(code(e), ErrorCode::Unauthorized);
}

#[tokio::test]
async fn password_guessing_is_limited() {
    let server = start_server().await;
    server.register("alice").await;

    let login = |conn: Connection, password: &'static str| async move {
        conn.request(Request::Login {
            name: "alice".into(),
            password: password.into(),
        })
        .await
    };

    // Three failures close the connection.
    let (conn, _) = server.connect().await;
    for _ in 0..3 {
        let e = login(conn.clone(), "wrong password").await.unwrap_err();
        assert!(
            matches!(e, e2emes_client::RequestError::Api(ref a) if a.code == ErrorCode::InvalidCredentials),
            "{e}"
        );
    }
    assert!(login(conn, PW).await.is_err());

    // Unknown names fail the same way as wrong passwords.
    let (conn, _) = server.connect().await;
    let e = conn
        .request(Request::Login {
            name: "nobody".into(),
            password: PW.into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(e, e2emes_client::RequestError::Api(ref a) if a.code == ErrorCode::InvalidCredentials));

    // After 10 failures from one address even the right password is refused for a while.
    for _ in 0..2 {
        let (conn, _) = server.connect().await;
        for _ in 0..3 {
            let _ = login(conn.clone(), "wrong password").await;
        }
    }
    let (conn, _) = server.connect().await;
    let e = login(conn, PW).await.unwrap_err();
    assert!(
        matches!(e, e2emes_client::RequestError::Api(ref a) if a.code == ErrorCode::TooManyAttempts),
        "{e}"
    );
}

#[tokio::test]
async fn requests_need_a_session() {
    let server = start_server().await;
    let (conn, _) = server.connect().await;
    assert!(matches!(conn.request(Request::Ping).await, Ok(Response::Pong)));
    let e = conn.request(Request::ListChats).await.unwrap_err();
    assert!(matches!(e, e2emes_client::RequestError::Api(ref a) if a.code == ErrorCode::Unauthorized));
}

#[tokio::test]
async fn wrong_server_key_is_refused() {
    let server = start_server().await;
    let impostor = StaticKeypair::generate().unwrap().public;
    assert!(connect(&server.addr, &impostor).await.is_err());
}

#[tokio::test]
async fn presence_and_other_devices() {
    let server = start_server().await;
    let (alice, mut alice_events, _, alice_phrase) = server.register("alice").await;
    let (bob, mut bob_events, _, bob_phrase) = server.register("bob").await;
    alice.request_chat("bob").await.unwrap();
    next_non_presence(&mut bob_events).await;
    bob.respond_chat("alice", true).await.unwrap();
    next_non_presence(&mut alice_events).await;

    // Chat partners see each other come and go.
    drop(bob);
    drop(bob_events);
    assert_eq!(
        next_event(&mut alice_events).await,
        Event::Presence {
            name: "bob".into(),
            online: false
        }
    );
    let (conn, mut bob_events) = server.connect().await;
    let (bob, _) = Messenger::login(conn, Store::in_memory().unwrap(), "bob", PW, &bob_phrase)
        .await
        .unwrap();
    assert_eq!(
        next_event(&mut alice_events).await,
        Event::Presence {
            name: "bob".into(),
            online: true
        }
    );

    // A message sent from one of alice's devices reaches bob and her other device.
    let (conn, mut alice2_events) = server.connect().await;
    let (alice2, _) = Messenger::login(conn, Store::in_memory().unwrap(), "alice", PW, &alice_phrase)
        .await
        .unwrap();
    alice.send("bob", "hello from the laptop").await.unwrap();

    for (m, events) in [(&bob, &mut bob_events), (&alice2, &mut alice2_events)] {
        let event = next_non_presence(events).await;
        let Notice::Message(msg) = m.handle_event(event).await.unwrap() else {
            panic!("expected a message");
        };
        assert_eq!((msg.from.as_str(), msg.to.as_str()), ("alice", "bob"));
        assert_eq!(msg.text.as_deref(), Ok("hello from the laptop"));
    }
}

#[tokio::test]
async fn sync_pages_through_history() {
    let server = start_server().await;
    let (alice, _alice_events, bob, _bob_events) = chat_pair(&server).await;
    for i in 0..5 {
        alice.send("bob", &format!("message {i}")).await.unwrap();
    }

    let (conn, _) = server.connect().await;
    let Response::Authenticated { .. } = conn
        .request(Request::Login {
            name: "bob".into(),
            password: PW.into(),
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    let Response::Messages { messages, more } = conn.request(Request::Sync { after_id: 0, limit: 3 }).await.unwrap()
    else {
        panic!()
    };
    assert_eq!((messages.len(), more), (3, true));
    let Response::Messages { messages: rest, more } = conn
        .request(Request::Sync {
            after_id: messages[2].id,
            limit: 3,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!((rest.len(), more), (2, false));

    // A fresh device of bob gets everything through Messenger::sync.
    let texts: Vec<_> = bob
        .history("alice", 100)
        .unwrap()
        .into_iter()
        .map(|m| m.text.unwrap())
        .collect();
    assert!(
        texts.is_empty(),
        "bob's first device only stores pushed or synced messages"
    );
    let synced = bob.sync().await.unwrap();
    assert_eq!(synced.len(), 5);
    assert_eq!(synced[4].text.as_deref(), Ok("message 4"));
}

#[tokio::test]
async fn changed_identity_key_blocks_the_chat() {
    let server = start_server().await;
    let (alice, mut alice_events, _, _) = server.register("alice").await;
    let store_path = temp_path("bob.db");
    let (conn, mut bob_events) = server.connect().await;
    let (bob, _, _) = Messenger::register(conn, Store::open(&store_path).unwrap(), "bob", PW)
        .await
        .unwrap();
    alice.request_chat("bob").await.unwrap();
    next_non_presence(&mut bob_events).await;
    bob.respond_chat("alice", true).await.unwrap();
    next_non_presence(&mut alice_events).await;

    // Make bob's pinned key for alice differ from the one the server reports. To bob's
    // client this looks exactly like the server swapping alice's key.
    rusqlite::Connection::open(&store_path)
        .unwrap()
        .execute(
            "UPDATE peers SET identity_key = ?1 WHERE name = 'alice'",
            [vec![9u8; 32]],
        )
        .unwrap();

    bob.chats().await.unwrap();
    assert!(bob.peer("alice").unwrap().unwrap().changed_key.is_some());
    assert!(matches!(bob.send("alice", "hi").await, Err(MessengerError::KeyChanged(name)) if name == "alice"));

    // After comparing safety numbers bob accepts the key, and the chat works again.
    let expected = e2emes_crypto::safety_number(&bob.public_key(), &alice.public_key());
    assert_eq!(bob.safety_number("alice").unwrap().unwrap(), expected);
    assert!(bob.accept_changed_key("alice").unwrap());
    assert!(!bob.peer("alice").unwrap().unwrap().verified);
    bob.send("alice", "hi").await.unwrap();
    let event = next_non_presence(&mut alice_events).await;
    let Notice::Message(msg) = alice.handle_event(event).await.unwrap() else {
        panic!("expected a message");
    };
    assert_eq!(msg.text.as_deref(), Ok("hi"));
}
