//! Password hashing, session tokens and login rate limiting.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Session lifetime.
pub const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Argon2id hash in PHC string format (`$argon2id$v=19$...`).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

/// Checks `password` against `stored`, or against a dummy hash when the user
/// doesn't exist, so both cases take the same time and don't reveal which names exist.
pub fn verify_password(password: &str, stored: Option<&str>) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY.get_or_init(|| hash_password("dummy password").expect("hashing a constant"));

    let Ok(parsed) = PasswordHash::new(stored.unwrap_or(dummy)) else {
        return false;
    };
    let ok = Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok();
    ok && stored.is_some()
}

/// A new random session token and the hash under which it is stored.
pub fn new_token() -> (String, [u8; 32]) {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let hash = token_hash(&token);
    (token, hash)
}

pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Counts failed logins per IP address within a sliding window.
pub struct LoginLimiter {
    max_failures: u32,
    window: Duration,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginLimiter {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            failures: Mutex::new(HashMap::new()),
        }
    }

    pub fn allowed(&self, ip: IpAddr) -> bool {
        let map = self.failures.lock().unwrap();
        match map.get(&ip) {
            Some(&(count, since)) => since.elapsed() > self.window || count < self.max_failures,
            None => true,
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut map = self.failures.lock().unwrap();
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() > self.window {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    pub fn forget_stale(&self) {
        let window = self.window;
        self.failures
            .lock()
            .unwrap()
            .retain(|_, (_, since)| since.elapsed() <= window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords() {
        let hash = hash_password("secret password").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("secret password", Some(&hash)));
        assert!(!verify_password("wrong", Some(&hash)));
        assert!(!verify_password("dummy password", None));
    }

    #[test]
    fn tokens_are_random_and_hashed() {
        let (a, ha) = new_token();
        let (b, _) = new_token();
        assert_ne!(a, b);
        assert_eq!(token_hash(&a), ha);
    }

    #[test]
    fn limiter_blocks_after_max_failures() {
        let limiter = LoginLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.allowed(ip));
        limiter.record_failure(ip);
        assert!(limiter.allowed(ip));
        limiter.record_failure(ip);
        assert!(!limiter.allowed(ip));
        assert!(limiter.allowed("10.0.0.2".parse().unwrap()));
    }
}
