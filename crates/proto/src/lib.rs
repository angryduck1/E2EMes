//! Wire protocol shared by the E2EMes server and client.
//!
//! Every TCP connection starts with a Noise `NK` handshake (the client knows the
//! server's static key in advance), after which each frame is a JSON document
//! encrypted with the Noise transport keys. See `docs/architecture.md`.

pub mod hexser;
pub mod messages;
pub mod transport;

pub use messages::*;

/// Length of every X25519 public key on the wire.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length used for end-to-end message encryption.
pub const NONCE_LEN: usize = 24;
/// Upper bound for an end-to-end ciphertext accepted by the server.
pub const MAX_CIPHERTEXT_LEN: usize = 16 * 1024;
/// Upper bound for a plaintext message typed by a user.
pub const MAX_TEXT_LEN: usize = MAX_CIPHERTEXT_LEN - 64;
/// Minimum account password length.
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum number of messages returned by one `Sync` request.
pub const MAX_SYNC_LIMIT: u32 = 500;

/// User names are 3-32 characters of `[A-Za-z0-9_-]`.
///
/// They end up in log lines and local file paths, so nothing else is allowed.
pub fn is_valid_name(name: &str) -> bool {
    (3..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_valid_name("alice"));
        assert!(is_valid_name("Bob_the-2nd"));
        assert!(!is_valid_name("al"));
        assert!(!is_valid_name("../evil"));
        assert!(!is_valid_name("with space"));
        assert!(!is_valid_name("кириллица"));
        assert!(!is_valid_name(&"a".repeat(33)));
    }
}
