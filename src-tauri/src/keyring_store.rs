//! VirusTotal API key in the OS credential vault. There is deliberately no
//! plaintext fallback: if no vault is available, saving the key fails.

use safefetch_core::secrets::{SecretStore, SecretString};
use safefetch_core::{Error, Result};

const SERVICE: &str = "io.github.safefetch.app";
const ACCOUNT: &str = "virustotal-api-key";

pub struct KeyringStore;

fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| Error::Secret(e.to_string()))
}

impl SecretStore for KeyringStore {
    fn get(&self) -> Result<Option<SecretString>> {
        match entry()?.get_password() {
            Ok(p) => Ok(Some(SecretString::new(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::Secret(e.to_string())),
        }
    }

    fn set(&self, value: &SecretString) -> Result<()> {
        entry()?.set_password(value.expose()).map_err(|e| {
            Error::Secret(format!(
                "could not save the key in the system keychain: {e}"
            ))
        })
    }

    fn delete(&self) -> Result<()> {
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::Secret(e.to_string())),
        }
    }
}
