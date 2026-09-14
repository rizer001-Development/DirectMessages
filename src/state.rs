//! Persistent state: config directory, keypair storage, and TOFU peer records.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::Identity;

#[derive(Serialize, Deserialize)]
struct StoredKeypair {
    secret: String,
}

/// The per-user config directory (created on demand).
///
/// Override with `DIRECTMESSAGES_CONFIG_DIR` for testing or portable setups;
/// otherwise defaults to `<config dir>/directmessages`.
pub fn config_dir() -> Result<PathBuf> {
    let dir = match std::env::var_os("DIRECTMESSAGES_CONFIG_DIR") {
        Some(override_dir) => PathBuf::from(override_dir),
        None => {
            let base = dirs::config_dir().context("could not locate the user config directory")?;
            base.join("directmessages")
        }
    };
    fs::create_dir_all(&dir).context("failed to create config directory")?;
    Ok(dir)
}

fn keypair_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("keypair.json"))
}

fn known_peers_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("known_peers.json"))
}

/// Load the stored keypair, or generate and store one on first run.
pub fn load_or_create_keypair() -> Result<Identity> {
    let path = keypair_path()?;
    if path.exists() {
        let text = fs::read_to_string(&path).context("failed to read keypair file")?;
        let stored: StoredKeypair =
            serde_json::from_str(&text).context("failed to parse keypair file")?;
        let secret = hex::decode(&stored.secret).context("invalid secret key encoding")?;
        let bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| anyhow!("secret key must be 32 bytes"))?;
        Ok(Identity::from_secret_bytes(bytes))
    } else {
        let identity = Identity::generate();
        save_keypair(&identity)?;
        Ok(identity)
    }
}

/// Generate a fresh keypair and overwrite any existing one.
pub fn generate_and_save() -> Result<Identity> {
    let identity = Identity::generate();
    save_keypair(&identity)?;
    Ok(identity)
}

fn save_keypair(identity: &Identity) -> Result<()> {
    let stored = StoredKeypair {
        secret: hex::encode(identity.secret.to_bytes()),
    };
    let text = serde_json::to_string_pretty(&stored).context("failed to serialize keypair")?;
    fs::write(keypair_path()?, text).context("failed to write keypair file")?;
    Ok(())
}

/// The result of checking a peer's fingerprint against stored TOFU state.
pub enum TrustDecision {
    /// This peer has never been seen under this identifier before.
    New,
    /// The fingerprint matches the previously stored one.
    Verified,
    /// The fingerprint changed since last time (possible MITM).
    Mismatch { expected: String },
}

/// Look up a peer identifier and compare its fingerprint.
pub fn check_peer(peer_id: &str, fingerprint: &str) -> Result<TrustDecision> {
    let peers = load_known_peers()?;
    match peers.get(peer_id) {
        None => Ok(TrustDecision::New),
        Some(expected) if expected == fingerprint => Ok(TrustDecision::Verified),
        Some(expected) => Ok(TrustDecision::Mismatch {
            expected: expected.clone(),
        }),
    }
}

/// Store (or overwrite) a peer's trusted fingerprint.
pub fn pin_peer(peer_id: &str, fingerprint: &str) -> Result<()> {
    let mut peers = load_known_peers()?;
    peers.insert(peer_id.to_string(), fingerprint.to_string());
    save_known_peers(&peers)
}

fn load_known_peers() -> Result<BTreeMap<String, String>> {
    let path = known_peers_path()?;
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let text = fs::read_to_string(&path).context("failed to read known peers file")?;
    if text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(&text).context("failed to parse known peers file")
}

fn save_known_peers(peers: &BTreeMap<String, String>) -> Result<()> {
    let text = serde_json::to_string_pretty(peers).context("failed to serialize known peers")?;
    fs::write(known_peers_path()?, text).context("failed to write known peers file")?;
    Ok(())
}

/// List all trusted peers as `(address, fingerprint)` pairs, sorted by address.
pub fn list_peers() -> Result<Vec<(String, String)>> {
    Ok(load_known_peers()?.into_iter().collect())
}

/// Remove a trusted peer record.
pub fn remove_peer(peer_id: &str) -> Result<()> {
    let mut peers = load_known_peers()?;
    peers.remove(peer_id);
    save_known_peers(&peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Env vars are process-global, so tests that set
    /// `DIRECTMESSAGES_CONFIG_DIR` must be serialized.
    static CONFIG_LOCK: Mutex<()> = Mutex::new(());

    /// Run the test body with `DIRECTMESSAGES_CONFIG_DIR` pointed at a unique
    /// temp directory, so tests never touch the real user config.
    fn with_isolated_config<T>(name: &str, f: impl FnOnce() -> T) -> T {
        let _guard: MutexGuard<'_, ()> = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join("directmessages-tests");
        let dir = base.join(format!("{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("DIRECTMESSAGES_CONFIG_DIR", &dir);
        let result = f();
        std::env::remove_var("DIRECTMESSAGES_CONFIG_DIR");
        let _ = fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn tofu_lifecycle_new_verified_mismatch_remove() {
        with_isolated_config("tofu-lifecycle", || {
            // First contact: the peer is new.
            assert!(matches!(
                check_peer("127.0.0.1", "a".repeat(64).as_str()),
                Ok(TrustDecision::New)
            ));

            // Pin it, and the same fingerprint verifies.
            pin_peer("127.0.0.1", &"a".repeat(64)).unwrap();
            assert!(matches!(
                check_peer("127.0.0.1", &"a".repeat(64)),
                Ok(TrustDecision::Verified)
            ));

            // A changed fingerprint must be flagged as a mismatch.
            assert!(matches!(
                check_peer("127.0.0.1", &"b".repeat(64)),
                Ok(TrustDecision::Mismatch { .. })
            ));

            // Removing an unknown peer is a harmless no-op; removing the
            // real one makes the peer look new again.
            remove_peer("127.0.1.1").unwrap();
            remove_peer("127.0.0.1").unwrap();
            assert!(matches!(
                check_peer("127.0.0.1", "a".repeat(64).as_str()),
                Ok(TrustDecision::New)
            ));
        });
    }

    #[test]
    fn list_peers_is_sorted_and_reflects_changes() {
        with_isolated_config("list-peers", || {
            assert!(list_peers().unwrap().is_empty());

            pin_peer("10.0.0.2", &"b".repeat(64)).unwrap();
            pin_peer("10.0.0.1", &"a".repeat(64)).unwrap();
            pin_peer("10.0.0.3", &"c".repeat(64)).unwrap();

            let peers = list_peers().unwrap();
            let addrs: Vec<&str> = peers.iter().map(|(a, _)| a.as_str()).collect();
            assert_eq!(addrs, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);

            remove_peer("10.0.0.2").unwrap();
            assert_eq!(list_peers().unwrap().len(), 2);
        });
    }

    #[test]
    fn keypair_persists_across_reloads() {
        with_isolated_config("keypair-persist", || {
            let first = load_or_create_keypair().unwrap();
            let second = load_or_create_keypair().unwrap();
            assert_eq!(*first.public.as_bytes(), *second.public.as_bytes());
        });
    }
}
