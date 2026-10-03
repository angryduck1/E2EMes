# E2EMes — end-to-end encrypted messenger in Rust. **BinBin**

Copyright (C) 2026 **BinBin**

![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust)
![Tokio](https://img.shields.io/badge/Tokio-async-blue)
![SQLite](https://img.shields.io/badge/SQLite-storage-lightgrey?logo=sqlite)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

## Overview

E2EMes is a console messenger with end-to-end encryption. This is the Rust rewrite
of the original C++ prototype.

- Messages are encrypted on the sender's device and decrypted only on the
  recipient's; the server stores ciphertext.
- The client authenticates the server by its public key (Noise `NK` handshake),
  and the connection has forward secrecy and replay protection.
- Identity keys are restored on a new device from a 12-word recovery phrase.
- Safety numbers let two users check that nobody swapped their keys.
- Chats need consent: a chat opens only after the other side accepts the request.

See [architecture.md](./architecture.md) for the protocol and the security model.

## Build

You need a stable Rust toolchain (install it with `rustup`). SQLite is bundled, nothing else
needs to be installed.

```sh
cargo build --release
cargo test
```

Binaries: `target/release/e2emes-server` and `target/release/e2emes`.

## Run

Server:

```sh
e2emes-server gen-key                      # writes server.key (secret) and server.pub
e2emes-server serve --listen 0.0.0.0:8088 --db e2emes.db --key server.key
```

Give `server.pub` to the users. Logging is controlled with `RUST_LOG`
(e.g. `RUST_LOG=debug`).

Client:

```sh
e2emes --server 127.0.0.1:8088 --server-key server.pub --data-dir ~/.e2emes
```

On the first start the client offers to register or to log in to an existing
account (name, password and recovery phrase). It then asks for a *local password*
that encrypts the account file on this device; later starts only ask for it.

| Command | Description |
|---------|-------------|
| `/chats` | list chats, pending requests and who is online |
| `/chat <name>` | ask `<name>` to start a chat |
| `/accept <name>` / `/reject <name>` | answer a chat request |
| `/msg <name> <text>` | send a message |
| `/history <name> [n]` | show the last `n` messages |
| `/verify <name>` | compare safety numbers and mark the contact verified |
| `/trust <name>` | accept a changed identity key of `<name>` |
| `/whoami`, `/logout`, `/quit`, `/help` | |

## Layout

| Crate | Purpose |
|-------|---------|
| `crates/proto` | message types, Noise transport, framing |
| `crates/crypto` | identity keys, end-to-end encryption, safety numbers, local vault |
| `crates/server` | the server (`e2emes-server`) and end-to-end tests in `tests/` |
| `crates/client` | client library (`Messenger`) and the console client (`e2emes`) |

### License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
See the [LICENSE](../LICENSE) file for the full text.
