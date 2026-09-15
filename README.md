# DirectMessages

Encrypted peer-to-peer messenger over TCP, written in Rust, with a full
terminal user interface (TUI).

Two peers each hold a persistent X25519 keypair. When they connect, they
exchange an ephemeral keypair plus their static key (64 bytes each side) and
derive a pair of directional ChaCha20-Poly1305 session keys via HKDF-SHA256
from a **quadruple ECDH** (ephemeral–ephemeral, static–static, and both cross
terms). Every message is encrypted and integrity-protected (AEAD) with a
per-message, per-direction nonce counter.

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

- **Confidentiality & integrity** — X25519 ECDH (static + ephemeral) +
  ChaCha20-Poly1305 (AEAD). An eavesdropper cannot read or modify messages.
- **Forward secrecy** — session keys mix in fresh ephemeral ECDH output, so
  compromising a long-term key cannot decrypt previously recorded sessions.
- **Unique session keys** — every session derives fresh keys, so the
  (key, nonce) pair is never reused across sessions.
- **Degenerate-key rejection** — all-zero peer public keys are rejected
  before key derivation.
- **Trust-on-first-use (TOFU)** — the first time you talk to a peer, its
  public-key fingerprint is shown, stored, and marked as trusted. On later
  connections, if the fingerprint changes, the app shows a security
  warning and pauses: press **U** to trust the new key and continue (only
  after verifying it out-of-band), or any other key to abort. You can also
  pin a fingerprint in advance, or delete a stale record, from the
  **Manage peers** screen.

## Fingerprint mismatch (recovering after a key change)

The warning fires whenever the stored fingerprint for a peer no longer
matches the live one. Common benign causes:

- the peer pressed **Regenerate keypair**;
- the stored record is stale or was created by an older test run.

Check the **expected** vs **got** fingerprints on the warning screen. If you
know the change is legitimate (regenerated key, your own test machine), press
**U** to re-pin and continue. If you cannot verify the new key out-of-band,
abort and investigate — that is the MITM scenario the check exists for.

## Testing on one machine

Both instances share one config directory and one keypair, and a listener
records peers by IP — so on localhost both roles resolve to the same TOFU
slot (`127.0.0.1`), which self-matches and never warns. To test two distinct
identities on one machine, isolate their configs:

```sh
# Terminal A
set DIRECTMESSAGES_CONFIG_DIR=%TEMP%\dm-a && directmessages

# Terminal B
set DIRECTMESSAGES_CONFIG_DIR=%TEMP%\dm-b && directmessages
```

(PowerShell: `$env:DIRECTMESSAGES_CONFIG_DIR = "$env:TEMP\dm-a"`.)
With isolated configs, B connecting to A produces a genuine "new peer" TOFU
record, and the full trust flow can be exercised safely.

### Known limitations

- The handshake itself is unauthenticated; a machine-in-the-middle during the
  very first connection (before TOFU pins the fingerprint) would be visible
  only through fingerprint verification out-of-band. A future version can add
  Ed25519 signatures over the ephemeral keys for explicit authentication.
- The listener records a peer's fingerprint keyed by the peer's IP address
  (not its port); two peers behind the same IP/NAT share a TOFU slot.
- The private key is stored in plaintext in the user config directory
  (`%APPDATA%\directmessages\keypair.json` on Windows, `~/.config/directmessages/`
  on Linux/macOS), protected by the user account's filesystem permissions.
- One chat session at a time.

## Configuration

State lives in the per-user config directory under `directmessages/`:

- `keypair.json` — the X25519 secret key (hex). The fingerprint of its public
  key is what TOFU pins; it does not change when ephemeral keys rotate.
- `known_peers.json` — TOFU map of peer address → trusted fingerprint.

## License

AGPL-3.0. See [LICENSE](LICENSE).
