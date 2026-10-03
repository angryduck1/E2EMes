//! Long-term identity keys.
//!
//! The 12-word phrase is a standard BIP-39 mnemonic (128 bits of entropy plus a
//! checksum). The X25519 secret is derived from its entropy with HKDF, so the same
//! phrase restores the same identity on any device, without help from the server.

use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{e2e::ChatKey, CryptoError, Result};

const IDENTITY_SALT: &[u8] = b"E2EMes identity v1";

pub struct Identity {
    secret: StaticSecret,
    public: [u8; 32],
}

impl Identity {
    /// Creates a new identity and returns it with its recovery phrase.
    pub fn generate() -> (Self, Zeroizing<String>) {
        let mnemonic = Mnemonic::generate_in(Language::English, 12).expect("12 is a valid word count");
        let phrase = Zeroizing::new(mnemonic.to_string());
        let identity = Self::from_entropy(&Zeroizing::new(mnemonic.to_entropy()));
        (identity, phrase)
    }

    /// Restores an identity from its recovery phrase. Case and extra spaces are ignored;
    /// a typo is caught by the BIP-39 checksum.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let normalized = Zeroizing::new(phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase());
        let mnemonic = Mnemonic::parse_in(Language::English, normalized.as_str())
            .map_err(|e| CryptoError::InvalidPhrase(e.to_string()))?;
        Ok(Self::from_entropy(&Zeroizing::new(mnemonic.to_entropy())))
    }

    fn from_entropy(entropy: &[u8]) -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(IDENTITY_SALT), entropy)
            .expand(b"x25519", secret.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        let secret = StaticSecret::from(*secret);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Key shared with the owner of `peer_public`; both sides derive the same one.
    pub fn chat_key(&self, peer_public: &[u8; 32]) -> Result<ChatKey> {
        ChatKey::derive(&self.secret, &self.public, peer_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_restores_same_identity() {
        let (identity, phrase) = Identity::generate();
        assert_eq!(phrase.split(' ').count(), 12);
        let shouty = format!("  {}  ", phrase.to_uppercase().replace(' ', "   "));
        assert_eq!(
            Identity::from_phrase(&shouty).unwrap().public_key(),
            identity.public_key()
        );
    }

    #[test]
    fn typo_is_rejected() {
        let (_, phrase) = Identity::generate();
        let mut words: Vec<&str> = phrase.split(' ').collect();
        words[3] = if words[3] == "abandon" { "ability" } else { "abandon" };
        // A single wrong word fails the checksum with probability 15/16; a different
        // phrase must at least never restore the original key.
        let changed = words.join(" ");
        match Identity::from_phrase(&changed) {
            Err(CryptoError::InvalidPhrase(_)) => {}
            Ok(other) => assert_ne!(other.public_key(), Identity::from_phrase(&phrase).unwrap().public_key()),
            Err(e) => panic!("{e}"),
        }
        assert!(Identity::from_phrase("not a valid phrase at all").is_err());
    }
}
