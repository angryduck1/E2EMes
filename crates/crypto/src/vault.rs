//! Password-protected storage for local secrets (session token, recovery phrase).
//!
//! Layout: `magic(8) | salt(16) | nonce(24) | XChaCha20-Poly1305(plaintext)`.
//! The key comes from Argon2id over the password. Every `seal` draws a fresh salt
//! and nonce, so a nonce is never reused under the same key.

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"E2EVLT01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(key)
}

pub fn seal(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .expect("encryption into a Vec can't fail");
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(password: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < HEADER_LEN + 16 || &data[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidVault);
    }
    let (header, ciphertext) = data.split_at(HEADER_LEN);
    let salt = &header[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce = XNonce::from_slice(&header[MAGIC.len() + SALT_LEN..]);
    let key = derive_key(password, salt)?;
    XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let sealed = seal(b"correct horse", b"secret token").unwrap();
        assert_eq!(open(b"correct horse", &sealed).unwrap().as_slice(), b"secret token");
        assert!(matches!(open(b"wrong", &sealed), Err(CryptoError::Decrypt)));

        let mut tampered = sealed.clone();
        tampered[10] ^= 1; // salt is authenticated too
        assert!(open(b"correct horse", &tampered).is_err());
        assert!(matches!(open(b"x", b"short"), Err(CryptoError::InvalidVault)));
    }

    #[test]
    fn every_seal_is_different() {
        let a = seal(b"pw", b"same").unwrap();
        let b = seal(b"pw", b"same").unwrap();
        assert_ne!(a[MAGIC.len()..HEADER_LEN], b[MAGIC.len()..HEADER_LEN]);
    }
}
