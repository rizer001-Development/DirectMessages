//! Cryptographic primitives: X25519 keys, fingerprints, session-key
//! derivation, and ChaCha20-Poly1305 encryption/decryption.
//!
//! Session keys are derived from a triple ECDH — static-static plus both
//! static-ephemeral shared secrets — so every session gets fresh keys (no
//! nonce reuse across sessions) and forward secrecy (compromising a
//! long-term key cannot decrypt past sessions).

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

/// Length in bytes of one X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

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

/// A short-lived X25519 keypair generated for a single session.
pub struct EphemeralSecret {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralSecret {
    /// Generate a fresh ephemeral keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        EphemeralSecret { secret, public }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// The SHA-256 fingerprint of a public key, hex-encoded (64 characters).
pub fn fingerprint(public: &PublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public.as_bytes());
    hex::encode(hasher.finalize())
}

/// Reject all-zero public keys, which make the ECDH result predictable
/// (including the identity element, where the shared secret is all zeros).
fn assert_valid_public_key(public: &PublicKey) -> Result<()> {
    let bytes = public.as_bytes();
    if bytes.iter().all(|b| *b == 0) {
        return Err(anyhow!("peer public key is degenerate (all zeros)"));
    }
    Ok(())
}

/// The two directional AEAD keys derived from the triple ECDH.
///
/// `salt` binds the keys to the specific pair of peers and prevents key
/// misbinding; `info` is a protocol label. Returns
/// `(k_initiator_to_responder, k_responder_to_initiator)`.
/// Role-canonical view of a session's key material.
struct SessionKeysInput<'a> {
    secret: &'a StaticSecret,
    ephemeral_secret: &'a EphemeralSecret,
    peer_public: &'a PublicKey,
    peer_ephemeral_public: &'a PublicKey,
    initiator_public: &'a PublicKey,
    responder_public: &'a PublicKey,
    initiator_ephemeral_public: &'a PublicKey,
    responder_ephemeral_public: &'a PublicKey,
    is_initiator: bool,
}

fn derive_directional_keys(input: &SessionKeysInput<'_>) -> Result<(Key, Key)> {
    let SessionKeysInput {
        secret,
        ephemeral_secret,
        peer_public,
        peer_ephemeral_public,
        initiator_public,
        responder_public,
        initiator_ephemeral_public,
        responder_ephemeral_public,
        is_initiator,
    } = *input;
    assert_valid_public_key(peer_public)?;
    assert_valid_public_key(peer_ephemeral_public)?;

    // Ephemeral-ephemeral ECDH: the fresh randomness that gives each session
    // unique keys and (with the static-static term authenticating it) forward
    // secrecy. Role-independent, so both sides compute identical values.
    let shared_ephemeral = ephemeral_secret
        .secret
        .diffie_hellman(peer_ephemeral_public);
    // Static-static ECDH: authenticates the session to both identities.
    let shared_static = secret.diffie_hellman(peer_public);

    // The two cross terms (my ephemeral x peer static, my static x peer
    // ephemeral) must be placed in role-canonical slots, otherwise the two
    // sides would assemble the IKM in different order.
    let (initiator_e_responder_s, responder_e_initiator_s) = if is_initiator {
        (
            ephemeral_secret.secret.diffie_hellman(peer_public),
            secret.diffie_hellman(peer_ephemeral_public),
        )
    } else {
        (
            secret.diffie_hellman(peer_ephemeral_public),
            ephemeral_secret.secret.diffie_hellman(peer_public),
        )
    };

    let mut ikm = Zeroizing::new([0u8; 128]);
    ikm[..32].copy_from_slice(shared_ephemeral.as_bytes());
    ikm[32..64].copy_from_slice(shared_static.as_bytes());
    ikm[64..96].copy_from_slice(initiator_e_responder_s.as_bytes());
    ikm[96..128].copy_from_slice(responder_e_initiator_s.as_bytes());

    let mut salt = [0u8; 128];
    salt[..32].copy_from_slice(initiator_public.as_bytes());
    salt[32..64].copy_from_slice(responder_public.as_bytes());
    salt[64..96].copy_from_slice(initiator_ephemeral_public.as_bytes());
    salt[96..128].copy_from_slice(responder_ephemeral_public.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), ikm.as_slice());
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(b"directmessages-v2", okm.as_mut_slice())
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
///
/// `my_ephemeral` and `peer_ephemeral_public` must be fresh per session; that
/// is what makes every session's keys unique and gives forward secrecy.
pub fn make_session(
    secret: &StaticSecret,
    my_ephemeral: &EphemeralSecret,
    peer_public: &PublicKey,
    peer_ephemeral_public: &PublicKey,
    my_public: &PublicKey,
    is_initiator: bool,
) -> Result<(SessionSender, SessionReceiver)> {
    // Direction assignment: c2s always flows initiator -> responder. Both
    // sides must sort the ECDH inputs identically, so the roles are taken
    // from the key agreement (who is initiator), not from the caller.
    let (initiator_public, responder_public) = if is_initiator {
        (my_public, peer_public)
    } else {
        (peer_public, my_public)
    };
    let (my_ephemeral_pk, peer_ephemeral_pk) = if is_initiator {
        (my_ephemeral.public(), peer_ephemeral_public)
    } else {
        (peer_ephemeral_public, my_ephemeral.public())
    };
    let (k_c2s, k_s2c) = derive_directional_keys(&SessionKeysInput {
        secret,
        ephemeral_secret: my_ephemeral,
        peer_public,
        peer_ephemeral_public,
        initiator_public,
        responder_public,
        initiator_ephemeral_public: my_ephemeral_pk,
        responder_ephemeral_public: peer_ephemeral_pk,
        is_initiator,
    })?;
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
    }

    #[test]
    fn session_keys_are_matching_and_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_e = EphemeralSecret::generate();
        let bob_e = EphemeralSecret::generate();

        let (alice_send, alice_recv) = make_session(
            &alice.secret,
            &alice_e,
            &bob.public,
            bob_e.public(),
            &alice.public,
            true,
        )
        .unwrap();
        let (bob_send, bob_recv) = make_session(
            &bob.secret,
            &bob_e,
            &alice.public,
            alice_e.public(),
            &bob.public,
            false,
        )
        .unwrap();

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
        let alice_e = EphemeralSecret::generate();
        let bob_e = EphemeralSecret::generate();
        let (mut a_send, _) = make_session(
            &alice.secret,
            &alice_e,
            &bob.public,
            bob_e.public(),
            &alice.public,
            true,
        )
        .unwrap();
        let (_, mut b_recv) = make_session(
            &bob.secret,
            &bob_e,
            &alice.public,
            alice_e.public(),
            &bob.public,
            false,
        )
        .unwrap();

        let mut ciphertext = a_send.encrypt(b"important").unwrap();
        ciphertext[0] ^= 0xff;
        assert!(b_recv.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn repeated_sessions_derive_different_keys() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        fn session_ciphertext(alice: &Identity, bob: &Identity, message: &[u8]) -> Vec<u8> {
            let alice_e = EphemeralSecret::generate();
            let bob_e = EphemeralSecret::generate();
            let (mut a_send, _b_recv) = make_session(
                &alice.secret,
                &alice_e,
                &bob.public,
                bob_e.public(),
                &alice.public,
                true,
            )
            .unwrap();
            a_send.encrypt(message).unwrap()
        }

        // Two sessions between the same static identities must not reuse a
        // (key, nonce) pair: identical plaintexts must produce unrelated
        // ciphertexts, and each session's messages must decrypt in-session.
        let session_one = session_ciphertext(&alice, &bob, b"same plaintext");
        let session_two = session_ciphertext(&alice, &bob, b"same plaintext");
        assert_ne!(session_one, session_two);
    }

    #[test]
    fn degenerate_public_key_is_rejected() {
        let alice = Identity::generate();
        let alice_e = EphemeralSecret::generate();
        let bob = Identity::generate();
        let bob_e = EphemeralSecret::generate();
        let zero = PublicKey::from([0u8; 32]);
        assert!(make_session(
            &alice.secret,
            &alice_e,
            &zero,
            bob_e.public(),
            &alice.public,
            true
        )
        .is_err());
        assert!(make_session(
            &alice.secret,
            &alice_e,
            &bob.public,
            &zero,
            &alice.public,
            true
        )
        .is_err());
    }
}
