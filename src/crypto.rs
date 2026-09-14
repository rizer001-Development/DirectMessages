//! Cryptographic primitives: X25519 keys, fingerprints, session-key
//! derivation, and ChaCha20-Poly1305 encryption/decryption.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The maximum length of a single message payload (in bytes).
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// A node's persistent identity: an X25519 secret key and its public key.
pub struct Identity {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }

    /// Rebuild an identity from a raw 32-byte secret key.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }
}

/// The SHA-256 fingerprint of a public key, hex-encoded (64 characters).
pub fn fingerprint(public: &PublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public.as_bytes());
    hex::encode(hasher.finalize())
}

/// A short, human-friendly form of the fingerprint.
pub fn short_fingerprint(public: &PublicKey) -> String {
    let fp = fingerprint(public);
    format!("fp:{}", &fp[..16])
}

/// The two directional AEAD keys derived from the ECDH shared secret.
///
/// `salt` binds the keys to the specific pair of peers and prevents key
/// misbinding; `info` is a protocol label. Returns
/// `(k_initiator_to_responder, k_responder_to_initiator)`.
fn derive_directional_keys(
    secret: &StaticSecret,
    peer_public: &PublicKey,
    initiator_public: &PublicKey,
    responder_public: &PublicKey,
) -> Result<(Key, Key)> {
    let shared_secret = secret.diffie_hellman(peer_public);
    let shared_bytes = Zeroizing::new(*shared_secret.as_bytes());

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(initiator_public.as_bytes());
    salt[32..].copy_from_slice(responder_public.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_bytes.as_slice());
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(b"directmessages-v1", okm.as_mut_slice())
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;

    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&okm[..32]);
    s2c.copy_from_slice(&okm[32..]);
    Ok((Key::from(c2s), Key::from(s2c)))
}

/// Encrypts messages in one direction of a session.
pub struct SessionSender {
    key: Key,
    counter: u64,
}

/// Decrypts messages from the opposite direction of a session.
pub struct SessionReceiver {
    key: Key,
    counter: u64,
}

/// Build the send/receive halves of a session for a given role.
pub fn make_session(
    secret: &StaticSecret,
    peer_public: &PublicKey,
    my_public: &PublicKey,
    is_initiator: bool,
) -> Result<(SessionSender, SessionReceiver)> {
    let (initiator_pk, responder_pk) = if is_initiator {
        (my_public, peer_public)
    } else {
        (peer_public, my_public)
    };
    let (k_c2s, k_s2c) = derive_directional_keys(secret, peer_public, initiator_pk, responder_pk)?;
    if is_initiator {
        Ok((SessionSender::new(k_c2s), SessionReceiver::new(k_s2c)))
    } else {
        Ok((SessionSender::new(k_s2c), SessionReceiver::new(k_c2s)))
    }
}

impl SessionSender {
    fn new(key: Key) -> Self {
        SessionSender { key, counter: 0 }
    }

    /// Encrypt a plaintext message for this direction.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = nonce_from_counter(self.counter);
        self.counter = self
            .counter
            .checked_add(1)
            .context("nonce counter overflow")?;
        cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("encryption failed: {e}"))
    }
}

impl SessionReceiver {
    fn new(key: Key) -> Self {
        SessionReceiver { key, counter: 0 }
    }

    /// Decrypt a ciphertext message from this direction.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = nonce_from_counter(self.counter);
        self.counter = self
            .counter
            .checked_add(1)
            .context("nonce counter overflow")?;
        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("decryption failed: {e}"))
    }
}

/// Build a 12-byte nonce from a per-direction message counter.
fn nonce_from_counter(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let identity = Identity::generate();
        let fp = fingerprint(&identity.public);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            short_fingerprint(&identity.public),
            format!("fp:{}", &fp[..16])
        );
    }

    #[test]
    fn session_keys_are_matching_and_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (alice_send, alice_recv) =
            make_session(&alice.secret, &bob.public, &alice.public, true).unwrap();
        let (bob_send, bob_recv) =
            make_session(&bob.secret, &alice.public, &bob.public, false).unwrap();

        // Alice -> Bob
        let mut a_send = alice_send;
        let mut b_recv = bob_recv;
        let ciphertext = a_send.encrypt(b"hello bob").unwrap();
        let plaintext = b_recv.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, b"hello bob");

        // Bob -> Alice
        let mut b_send = bob_send;
        let mut a_recv = alice_recv;
        let ciphertext = b_send.encrypt(b"hello alice").unwrap();
        let plaintext = a_recv.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, b"hello alice");
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut a_send, _) =
            make_session(&alice.secret, &bob.public, &alice.public, true).unwrap();
        let (_, mut b_recv) = make_session(&bob.secret, &alice.public, &bob.public, false).unwrap();

        let mut ciphertext = a_send.encrypt(b"important").unwrap();
        ciphertext[0] ^= 0xff;
        assert!(b_recv.decrypt(&ciphertext).is_err());
    }
}
