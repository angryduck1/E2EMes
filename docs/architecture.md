# Architecture

```text
 ┌──────────── client (e2emes) ────────────┐            ┌────────── server (e2emes-server) ──────────┐
 │ console UI (main.rs)                     │            │ accept loop (lib.rs)                        │
 │   └─ Messenger: keys, pinning, sync      │   Noise    │   └─ one task per connection (conn.rs)      │
 │        ├─ Connection: requests/events ───┼── NK over ─┼──────┤                                      │
 │        ├─ Store: local SQLite            │    TCP     │      ├─ Hub: online users → event queues    │
 │        └─ vault: account.vault           │            │      └─ Db: SQLite (users, sessions, chats, │
 └──────────────────────────────────────────┘            │             requests, messages)             │
                                                         └─────────────────────────────────────────────┘
```

## Transport

Every connection starts with a [Noise](https://noiseprotocol.org) handshake,
`Noise_NK_25519_ChaChaPoly_BLAKE2s` (`crates/proto/src/transport.rs`):

- the client knows the server's static key in advance (`server.pub`), so it talks
  only to the real server: a wrong key fails the handshake;
- transport keys come from fresh ephemeral keys, so recorded traffic stays secret
  even if `server.key` leaks later (forward secrecy);
- each direction uses a counter nonce, so a replayed, dropped or reordered frame
  fails to decrypt and the connection closes.

On the wire every Noise message is `u32` big-endian length + payload (at most
65535 bytes). Inside is one JSON document.

## Protocol

Types live in `crates/proto/src/messages.rs`. The client sends
`ClientFrame { id, request }`; the server replies with
`ServerFrame::Response { id, result }` and may push `ServerFrame::Event` at any
time, so new messages arrive without polling.

| Request | Needs login | Result |
|---------|-------------|--------|
| `register {name, password, identity_key}` | no | `authenticated {name, token, identity_key}` |
| `login {name, password}` | no | `authenticated` (new token) |
| `resume {token}` | no | `authenticated` |
| `ping` | no | `pong` |
| `logout` | yes | `ok`, token revoked, connection closed |
| `lookup_user {name}` | yes | `user {name, identity_key, online}` |
| `request_chat {name}` | yes | `chat_status {user, open}` |
| `respond_chat {name, accept}` | yes | `chat_status {user, open}` |
| `list_chats` | yes | `chats {chats, incoming, outgoing}` |
| `send_message {to, nonce, ciphertext}` | yes | `message_accepted {id, timestamp}` |
| `sync {after_id, limit}` | yes | `messages {messages, more}` |

Events: `new_message`, `chat_request`, `chat_accepted`, `presence {name, online}`.
Errors carry a code (`name_taken`, `invalid_credentials`, `too_many_attempts`,
`not_a_chat`, …) and a message.

## Accounts and keys

There are three secrets, as in the original design:

| Secret | Where | Protects |
|--------|-------|----------|
| account password | user's head; server keeps an Argon2id hash | logging in on a new device |
| recovery phrase (12 BIP-39 words) | user's paper; encrypted in the local vault | the identity key |
| local password | user's head | `account.vault` on this device |

- The **identity key** is an X25519 key derived from the phrase's entropy with
  HKDF-SHA256 (`crates/crypto/src/identity.rs`). The server only stores the public
  half; a login on a new device checks that the phrase gives the same key.
- **Sessions**: `login`/`register` return a random 256-bit token. The server stores
  only its SHA-256 and expires it after 30 days. `logout` revokes it.
- **Vault** (`crates/crypto/src/vault.rs`): name, token and phrase, sealed with
  XChaCha20-Poly1305 under a key from Argon2id(local password). Every save uses a
  fresh salt and nonce.

## End-to-end encryption

`crates/crypto/src/e2e.rs`:

1. chat key = HKDF-SHA256(X25519(my identity secret, peer identity key),
   salt = both public keys in sorted order);
2. each message = XChaCha20-Poly1305(chat key, random 192-bit nonce,
   associated data = `sender \0 recipient`), so the server can't re-label a
   ciphertext as coming from someone else or going the other way.

**Key pinning.** The client remembers each peer's identity key the first time it
sees it (`peers` table of the local store). If the server ever reports another key,
the client stops sending to and decrypting from that peer and asks the user to
compare **safety numbers** (`/verify`) and then accept the key (`/trust`). Safety
numbers are 12 groups of 5 digits from BLAKE2b over both keys, identical on both sides.

## Server

- `conn.rs` handles one connection: 10 s handshake timeout, 30 s to log in,
  90 s idle timeout (clients ping every 30 s), at most 3 failed logins per connection.
- `auth.rs`: Argon2id password hashes (verification against a dummy hash for unknown
  names, so timing doesn't reveal which names exist), session tokens, and a per-IP
  limiter (10 failed logins per 15 minutes). At most 4 Argon2 runs at a time.
- `db.rs`: SQLite in WAL mode, accessed from the blocking pool. Names are unique
  case-insensitively and limited to `[A-Za-z0-9_-]{3,32}`. Chat requests and chats
  are separate tables: answering a request that doesn't exist is an error, so a
  chat can't be forced on anyone.
- `hub.rs`: online users and their connections. Presence changes are pushed to chat
  partners; a sent message is pushed to the recipient and to the sender's other devices.

## Client

- `connection.rs` matches responses to requests by `id` and hands events to the UI.
- `messenger.rs` does key pinning, encryption, `sync` (pages of 500 after the
  highest locally stored id) and turns events into notices.
- `store.rs` keeps pinned keys and the message history *still encrypted*;
  messages are decrypted when shown.
- `main.rs` reads all input from one place, so prompts and commands never compete
  for stdin.

## Known limitations

- **No forward secrecy for messages.** The chat key is static: whoever learns an
  identity secret (the phrase) can read that user's whole history. The next step is
  a ratcheting protocol, e.g. Olm via the `vodozemac` crate or the Signal protocol
  via `libsignal` (AGPL-3.0, compatible with this project).
- Trust on first use: until two users compare safety numbers, a malicious server
  could hand out a fake key at the very first contact.
- The server sees metadata: who talks to whom, when, message sizes and online status.
- No group chats, no attachments, no deleting messages.

## Changes from the C++ version

| C++ prototype | Rust version |
|---------------|--------------|
| `crypto_kx` + `secretbox`, random nonces, no replay protection | Noise `NK`: server auth, forward secrecy, counter nonces |
| magic JSON codes 100–900, lock-step request/response, polling every 5 s | typed requests/responses with ids, server push |
| thread per connection, no read timeouts | Tokio tasks, handshake/auth/idle timeouts, connection limit |
| Redis + SQLite | one SQLite database |
| plaintext passwords in Redis | Argon2id hashes, per-IP limit, constant-time failures |
| one nonce for two `secretbox`es in `session_token.data` | vault sealed once per save with fresh salt and nonce |
| registration could overwrite an existing name; chats could be forced | unique names in the database; only real requests can be accepted |
| custom 12-word list without checksum, key via Argon2 with server salt | standard BIP-39 with checksum, HKDF, no server input |
| no key verification | key pinning, safety numbers, key-change blocking |
