//! Cryptography of E2EMes clients.
//!
//! - [`identity`]: the long-term X25519 identity key, derived from a 12-word BIP-39 phrase.
//! - [`e2e`]: per-chat keys between two identities, message encryption and safety numbers.
//! - [`vault`]: password-protected local storage of the account secrets.

pub mod e2e;
pub mod identity;
pub mod vault;

pub use e2e::{safety_number, ChatKey};
pub use identity::Identity;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid recovery phrase: {0}")]
    InvalidPhrase(String),
    #[error("peer key is invalid (low-order point)")]
    WeakKey,
    #[error("decryption failed: wrong key or tampered data")]
    Decrypt,
    #[error("vault file is corrupted or has an unknown format")]
    InvalidVault,
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
