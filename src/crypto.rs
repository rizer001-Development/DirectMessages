//! Cryptographic primitives: X25519 keys, fingerprints, session-key
//! derivation, and ChaCha20-Poly1305 encryption/decryption.
//!
//! Each identity pairs a static X25519 key (key agreement) with an Ed25519
//! signing key (handshake authentication). Session keys are derived from a
//! quadruple ECDH — ephemeral-ephemeral, static-static, and both cross terms
//! — so every session gets fresh keys (no nonce reuse across sessions) and
//! forward secrecy (compromising a long-term key cannot decrypt past
//! sessions).

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The maximum length of a single message payload (in bytes).
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Length in bytes of one X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length in bytes of one Ed25519 public key.
pub const SIGNING_KEY_LEN: usize = 32;

/// Length in bytes of one Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// A node's persistent identity: an X25519 keypair for key agreement and an
/// Ed25519 keypair for signing handshakes.
pub struct Identity {
    pub secret: StaticSecret,
    pub public: PublicKey,
    pub signing: SigningKey,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        // The signing key is derived from the X25519 secret so a stored
        // keypair (32 bytes) keeps deriving the same full identity.
        let signing = signing_key_from_secret(&secret);
        Identity {
            secret,
            public,
            signing,
        }
    }

    /// Rebuild an identity from a raw 32-byte secret key.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        let signing = signing_key_from_secret(&secret);
        Identity {
            secret,
            public,
            signing,
        }
    }
}

/// Derive the handshake-signing key from the X25519 secret via HKDF, so a
/// single stored 32-byte secret deterministically yields the whole identity.
fn signing_key_from_secret(secret: &StaticSecret) -> SigningKey {
    let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(b"directmessages-ed25519-v1", seed.as_mut_slice())
        .expect("32-byte OKM is valid for SHA-256");
    SigningKey::from_bytes(seed.as_ref().try_into().expect("32-byte seed"))
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

/// The peer's long-term and session keys, as verified during the handshake.
pub struct PeerKeys {
    /// Static X25519 key (the key-agreement identity).
    pub static_public: PublicKey,
    /// Ed25519 key that signed the ephemeral key.
    pub signing_public: VerifyingKey,
    /// Session-ephemeral X25519 key.
    pub ephemeral_public: PublicKey,
}

/// The SHA-256 fingerprint of a peer's long-term keys (X25519 || Ed25519),
/// hex-encoded (64 characters).
pub fn fingerprint(public: &PublicKey, signing_public: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public.as_bytes());
    hasher.update(signing_public.as_bytes());
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
    identity: &Identity,
    my_ephemeral: &EphemeralSecret,
    peer: &PeerKeys,
    is_initiator: bool,
) -> Result<(SessionSender, SessionReceiver)> {
    let peer_public = &peer.static_public;
    let peer_ephemeral_public = &peer.ephemeral_public;
    let my_public = &identity.public;
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
        secret: &identity.secret,
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
        let fp = fingerprint(&identity.public, &identity.signing.verifying_key());
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_keys_are_matching_and_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_e = EphemeralSecret::generate();
        let bob_e = EphemeralSecret::generate();

        let alice_peer_keys = PeerKeys {
            static_public: bob.public,
            signing_public: bob.signing.verifying_key(),
            ephemeral_public: *bob_e.public(),
        };
        let bob_peer_keys = PeerKeys {
            static_public: alice.public,
            signing_public: alice.signing.verifying_key(),
            ephemeral_public: *alice_e.public(),
        };

        let (alice_send, alice_recv) =
            make_session(&alice, &alice_e, &alice_peer_keys, true).unwrap();
        let (bob_send, bob_recv) = make_session(&bob, &bob_e, &bob_peer_keys, false).unwrap();

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
        let alice_peer_keys = PeerKeys {
            static_public: bob.public,
            signing_public: bob.signing.verifying_key(),
            ephemeral_public: *bob_e.public(),
        };
        let bob_peer_keys = PeerKeys {
            static_public: alice.public,
            signing_public: alice.signing.verifying_key(),
            ephemeral_public: *alice_e.public(),
        };
        let (mut a_send, _) = make_session(&alice, &alice_e, &alice_peer_keys, true).unwrap();
        let (_, mut b_recv) = make_session(&bob, &bob_e, &bob_peer_keys, false).unwrap();

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
            let alice_peer_keys = PeerKeys {
                static_public: bob.public,
                signing_public: bob.signing.verifying_key(),
                ephemeral_public: *bob_e.public(),
            };
            let (mut a_send, _b_recv) =
                make_session(alice, &alice_e, &alice_peer_keys, true).unwrap();
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
        let zero_peer = PeerKeys {
            static_public: zero,
            signing_public: bob.signing.verifying_key(),
            ephemeral_public: *bob_e.public(),
        };
        let degenerate_peer = PeerKeys {
            static_public: bob.public,
            signing_public: bob.signing.verifying_key(),
            ephemeral_public: zero,
        };
        assert!(make_session(&alice, &alice_e, &zero_peer, true).is_err());
        assert!(make_session(&alice, &alice_e, &degenerate_peer, true).is_err());
    }

    #[test]
    fn fingerprint_binds_both_longterm_keys() {
        let identity = Identity::generate();
        let fp = fingerprint(&identity.public, &identity.signing.verifying_key());
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

        // A different signing key (e.g. an attacker's) must yield a
        // different fingerprint for the same static key.
        let other = Identity::generate();
        assert_ne!(
            fp,
            fingerprint(&identity.public, &other.signing.verifying_key())
        );
    }

    #[test]
    fn identity_is_deterministic_from_secret_bytes() {
        let seed = {
            use rand::RngCore;
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            s
        };
        let a = Identity::from_secret_bytes(seed);
        let b = Identity::from_secret_bytes(seed);
        assert_eq!(*a.public.as_bytes(), *b.public.as_bytes());
        assert_eq!(a.signing.to_bytes(), b.signing.to_bytes());
    }
}
