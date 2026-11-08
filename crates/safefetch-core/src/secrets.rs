//! Secret handling. The core only knows the [`SecretStore`] trait; the
//! desktop app implements it with the OS keyring.

use std::fmt;
use std::sync::Mutex;

use crate::error::Result;

/// A string that never shows up in `Debug`/`Display` output or logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// Explicit access; grep for `expose` to audit every use.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // Best-effort wipe; the allocator may still have copies.
        let len = self.0.len();
        self.0.clear();
        self.0.extend(std::iter::repeat_n('\0', len));
    }
}

pub trait SecretStore: Send + Sync {
    fn get(&self) -> Result<Option<SecretString>>;
    fn set(&self, value: &SecretString) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

/// In-memory store for tests and for running without a keyring.
#[derive(Default)]
pub struct MemorySecretStore(Mutex<Option<SecretString>>);

impl SecretStore for MemorySecretStore {
    fn get(&self) -> Result<Option<SecretString>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| crate::Error::Secret("poisoned".into()))?
            .clone())
    }
    fn set(&self, value: &SecretString) -> Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| crate::Error::Secret("poisoned".into()))? = Some(value.clone());
        Ok(())
    }
    fn delete(&self) -> Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| crate::Error::Secret("poisoned".into()))? = None;
        Ok(())
    }
}

/// VirusTotal keys are 64 lowercase hex characters.
pub fn validate_vt_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_redacted() {
        let s = SecretString::new("supersecret");
        assert_eq!(format!("{s:?}"), "SecretString(<redacted>)");
        assert_eq!(format!("{s}"), "<redacted>");
        assert_eq!(s.expose(), "supersecret");
    }

    #[test]
    fn key_format() {
        assert!(validate_vt_key(&"a".repeat(64)));
        assert!(!validate_vt_key("short"));
        assert!(!validate_vt_key(&"g".repeat(64)));
    }
}
