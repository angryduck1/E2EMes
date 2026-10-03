//! End-to-end message encryption between two identities.
//!
//! Both users derive the same chat key from X25519 between their identity keys,
//! fed through HKDF together with both public keys. Messages are sealed with
//! XChaCha20-Poly1305 under a random 192-bit nonce, and the sender and recipient
//! names are authenticated as associated data, so the server can't re-label or
//! reflect a ciphertext into another conversation or direction.
//!
//! This scheme has no forward secrecy: whoever later learns an identity secret can
//! read the whole history of its chats. See `docs/architecture.md`.

use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

const NONCE_LEN: usize = 24;

pub struct ChatKey(Zeroizing<[u8; 32]>);

fn ordered<'a>(a: &'a [u8; 32], b: &'a [u8; 32]) -> (&'a [u8; 32], &'a [u8; 32]) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn aad(from: &str, to: &str) -> Vec<u8> {
    let mut aad = b"E2EMes msg v1\0".to_vec();
    aad.extend_from_slice(from.as_bytes());
    aad.push(0);
    aad.extend_from_slice(to.as_bytes());
    aad
}

impl ChatKey {
    pub(crate) fn derive(secret: &StaticSecret, own_public: &[u8; 32], peer_public: &[u8; 32]) -> Result<Self> {
        let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
        if !shared.was_contributory() {
            return Err(CryptoError::WeakKey);
        }
        let (lo, hi) = ordered(own_public, peer_public);
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(lo);
        salt[32..].copy_from_slice(hi);

        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
            .expand(b"E2EMes chat key v1", key.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        Ok(Self(key))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.0.as_ref().into())
    }

    /// Returns `(nonce, ciphertext)`.
    pub fn encrypt(&self, from: &str, to: &str, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = aad(from, to);
        let ciphertext = self
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("encryption into a Vec can't fail");
        (nonce.to_vec(), ciphertext)
    }

    pub fn decrypt(&self, from: &str, to: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::Decrypt);
        }
        let aad = aad(from, to);
        self.cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// A number both users can compare over another channel (in person, by phone).
/// If it matches, nobody, including the server, swapped their identity keys.
///
/// It is the same for both sides: 12 groups of 5 digits from BLAKE2b over the two
/// keys in sorted order.
pub fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
    let (lo, hi) = ordered(a, b);
    let digest = Blake2b512::new()
        .chain_update(b"E2EMes safety number v1")
        .chain_update(lo)
        .chain_update(hi)
        .finalize();
    digest
        .chunks(5)
        .take(12)
        .map(|chunk| {
            let value = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use crate::Identity;

    use super::*;

    #[test]
    fn both_sides_share_a_key() {
        let (alice, _) = Identity::generate();
        let (bob, _) = Identity::generate();
        let a = alice.chat_key(&bob.public_key()).unwrap();
        let b = bob.chat_key(&alice.public_key()).unwrap();

        let (nonce, ct) = a.encrypt("alice", "bob", "привет".as_bytes());
        assert_eq!(b.decrypt("alice", "bob", &nonce, &ct).unwrap(), "привет".as_bytes());

        // Re-labelled direction, tampered ciphertext or a third party: all rejected.
        assert!(b.decrypt("bob", "alice", &nonce, &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(b.decrypt("alice", "bob", &nonce, &bad).is_err());
        let (eve, _) = Identity::generate();
        assert!(eve
            .chat_key(&alice.public_key())
            .unwrap()
            .decrypt("alice", "bob", &nonce, &ct)
            .is_err());

        // Fresh nonce every time.
        let (nonce2, _) = a.encrypt("alice", "bob", b"x");
        assert_ne!(nonce, nonce2);
    }

    #[test]
    fn low_order_key_rejected() {
        let (alice, _) = Identity::generate();
        assert!(matches!(alice.chat_key(&[0u8; 32]), Err(CryptoError::WeakKey)));
    }

    #[test]
    fn safety_number_is_symmetric() {
        let (alice, _) = Identity::generate();
        let (bob, _) = Identity::generate();
        let n = safety_number(&alice.public_key(), &bob.public_key());
        assert_eq!(n, safety_number(&bob.public_key(), &alice.public_key()));
        assert_eq!(n.split(' ').count(), 12);
        let (eve, _) = Identity::generate();
        assert_ne!(n, safety_number(&alice.public_key(), &eve.public_key()));
    }
}
