# DirectMessages

Encrypted peer-to-peer messenger over TCP, written in Rust.

Two peers each hold a persistent X25519 keypair. When they connect, they
perform an X25519 key exchange (ECDH) and derive a pair of directional
ChaCha20-Poly1305 session keys via HKDF-SHA256. Every message is encrypted
and integrity-protected (AEAD) with a per-message, per-direction nonce
counter.

## Building

```sh
cargo build --release
```

The binary is `target/release/directmessages` (or `directmessages.exe`).

## Usage

```sh
# Show this node's fingerprint
directmessages fingerprint

# Wait for an incoming connection, then chat
directmessages listen 9000

# Connect to a peer, then chat
directmessages connect 127.0.0.1 9000

# Generate a fresh keypair (overwrites the existing one)
directmessages keygen

# Manually pin a peer's fingerprint to an address (optional)
directmessages trust <FINGERPRINT> <HOST:PORT>
```

Inside a chat session, type a line and press Enter to send it. Type `/quit`
(or `/exit`) to leave; `Ctrl-D` (or `Ctrl-Z` on Windows) also exits.

## Security model

- **Confidentiality & integrity** — X25519 ECDH + ChaCha20-Poly1305 (AEAD).
  An eavesdropper cannot read or modify messages.
- **Trust-on-first-use (TOFU)** — the first time you talk to a peer, its
  public-key fingerprint is shown, stored, and marked as trusted. On later
  connections, if the fingerprint changes, the connection is refused as a
  possible man-in-the-middle attack. For strong assurance, compare the
  displayed fingerprint with the peer out-of-band (in person, by phone, etc.)
  on first contact.

### Known limitations (v1)

- **No forward secrecy** — the long-term X25519 keys are used directly, so
  compromising one of them would decrypt all past and future sessions with
  that peer. A future version can add ephemeral session keys signed by a
  long-term Ed25519 identity.
- The listener records a peer's fingerprint keyed by the peer's IP address
  (not its port); two peers behind the same IP/NAT share a TOFU slot.
- The private key is stored in plaintext in the user config directory
  (`%APPDATA%\directmessages\keypair.json` on Windows, `~/.config/directmessages/`
  on Linux/macOS), protected by the user account's filesystem permissions.
- Incoming messages print with a simple `[peer]` prefix; there is no fancy
  line editing or history yet.

## Configuration

State lives in the per-user config directory under `directmessages/`:

- `keypair.json` — the X25519 secret key (hex).
- `known_peers.json` — TOFU map of peer address → trusted fingerprint.

## License

AGPL-3.0. See [LICENSE](LICENSE).
