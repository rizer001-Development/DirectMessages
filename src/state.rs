//! Persistent state: config directory, keypair storage, and TOFU peer records.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{fingerprint, short_fingerprint, Identity};

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

/// Short fingerprint for human-facing output.
pub fn display_fingerprint(identity: &Identity) -> String {
    short_fingerprint(&identity.public)
}

/// Full 64-hex fingerprint, used for verification and the `trust` command.
pub fn full_fingerprint(identity: &Identity) -> String {
    fingerprint(&identity.public)
}
