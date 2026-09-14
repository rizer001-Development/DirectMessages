# DirectMessages

Encrypted peer-to-peer messenger over TCP, written in Rust, with a full
terminal user interface (TUI).

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

Run the program without arguments to open the interactive interface:

```sh
directmessages
```

The menu offers everything the app can do:

- **Connect to peer** — enter a host/IP and port, connect, and start chatting.
- **Listen for connection** — bind a port and wait for a peer to connect.
- **Manage peers** — list, add, and remove trusted peers (TOFU records).
- **Regenerate keypair** — replace your identity; the new fingerprint is shown.
- **Quit**.

Keys:

| Screen      | Keys |
| ----------- | ---- |
| Menu        | ↑/↓ select · Enter choose · 1–5 shortcut · q/Esc quit |
| Forms       | type to enter text · Backspace delete · Tab/↑/↓ switch field · Enter confirm · Esc back |
| Peers       | ↑/↓ select · a add · r remove · Esc back |
| Chat        | Enter send · ↑/↓ / PgUp/PgDn scroll history · /quit or Esc leave |

Configuration directory override: set `DIRECTMESSAGES_CONFIG_DIR` to a path
(useful for portable setups or tests).

## Security model

- **Confidentiality & integrity** — X25519 ECDH + ChaCha20-Poly1305 (AEAD).
  An eavesdropper cannot read or modify messages.
- **Trust-on-first-use (TOFU)** — the first time you talk to a peer, its
  public-key fingerprint is shown, stored, and marked as trusted. On later
  connections, if the fingerprint changes, the connection is refused with a
  security warning as a possible man-in-the-middle attack. For strong
  assurance, compare the displayed fingerprint with the peer out-of-band
  (in person, by phone, etc.) on first contact. You can also pin a
  fingerprint in advance from the **Manage peers** screen.

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
- One chat session at a time.

## Configuration

State lives in the per-user config directory under `directmessages/`:

- `keypair.json` — the X25519 secret key (hex).
- `known_peers.json` — TOFU map of peer address → trusted fingerprint.

## License

AGPL-3.0. See [LICENSE](LICENSE).
