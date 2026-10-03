//! The account file kept on the device, encrypted with the local password.

use std::{fs, path::Path};

use anyhow::Context;
use e2emes_crypto::vault;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AccountVault {
    pub name: String,
    pub token: String,
    /// The recovery phrase; the identity key is re-derived from it on start.
    pub phrase: String,
}

impl AccountVault {
    pub fn save(&self, path: &Path, password: &str) -> anyhow::Result<()> {
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        let sealed = vault::seal(password.as_bytes(), &plain)?;
        // Write to a temporary file first so a crash never leaves a half-written vault.
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, sealed).with_context(|| format!("writing {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path, password: &str) -> anyhow::Result<Self> {
        let sealed = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let plain = vault::open(password.as_bytes(), &sealed)
            .map_err(|_| anyhow::anyhow!("wrong local password or damaged {}", path.display()))?;
        Ok(serde_json::from_slice(&plain)?)
    }
}
