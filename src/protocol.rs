//! Wire protocol: the X25519 handshake and length-prefixed message framing.

use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use x25519_dalek::PublicKey;

use crate::crypto::{Identity, SessionReceiver, SessionSender, MAX_MESSAGE_LEN};

/// Exchange public keys and derive the session keys.
///
/// The initiator sends its public key first; the responder replies with its
/// own. Both sides then derive the same pair of directional keys.
pub fn perform_handshake<S: Read + Write>(
    stream: &mut S,
    is_initiator: bool,
    identity: &Identity,
) -> Result<(SessionSender, SessionReceiver, PublicKey)> {
    let mut peer_bytes = [0u8; 32];

    if is_initiator {
        stream
            .write_all(identity.public.as_bytes())
            .context("failed to send public key")?;
        stream.flush().context("failed to flush public key")?;
        stream
            .read_exact(&mut peer_bytes)
            .context("failed to read peer public key")?;
    } else {
        stream
            .read_exact(&mut peer_bytes)
            .context("failed to read peer public key")?;
        stream
            .write_all(identity.public.as_bytes())
            .context("failed to send public key")?;
        stream.flush().context("failed to flush public key")?;
    }

    let peer_public = PublicKey::from(peer_bytes);
    let (sender, receiver) = crate::crypto::make_session(
        &identity.secret,
        &peer_public,
        &identity.public,
        is_initiator,
    )?;

    Ok((sender, receiver, peer_public))
}

/// Write a single length-prefixed frame.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Read a single length-prefixed frame.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, b"").unwrap();
        write_frame(&mut buf, b"world!").unwrap();

        let mut cursor = Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).unwrap(), b"hello");
        assert_eq!(read_frame(&mut cursor).unwrap(), b"");
        assert_eq!(read_frame(&mut cursor).unwrap(), b"world!");
    }

    #[test]
    fn frame_rejects_oversized_length() {
        // A length prefix larger than MAX_MESSAGE_LEN must be rejected
        // before we try to allocate it.
        let len = (MAX_MESSAGE_LEN as u32) + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);

        let err = read_frame(&mut Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_detects_truncated_body() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(b"ab"); // only 2 of 5 bytes

        let err = read_frame(&mut Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn handshake_over_tcp_roundtrip() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        use crate::crypto::Identity;

        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_public_bytes = *alice.public.as_bytes();
        let bob_public_bytes = *bob.public.as_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (sender, receiver, peer_pk) = perform_handshake(&mut stream, false, &bob).unwrap();

            let mut send = sender;
            let ciphertext = send.encrypt(b"from-server").unwrap();
            write_frame(&mut stream, &ciphertext).unwrap();

            let frame = read_frame(&mut stream).unwrap();
            let mut recv = receiver;
            let plaintext = recv.decrypt(&frame).unwrap();

            (*peer_pk.as_bytes(), plaintext)
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let (sender, receiver, peer_pk) = perform_handshake(&mut stream, true, &alice).unwrap();
        assert_eq!(*peer_pk.as_bytes(), bob_public_bytes);

        let frame = read_frame(&mut stream).unwrap();
        let mut recv = receiver;
        let plaintext = recv.decrypt(&frame).unwrap();
        assert_eq!(plaintext, b"from-server");

        let mut send = sender;
        let ciphertext = send.encrypt(b"from-client").unwrap();
        write_frame(&mut stream, &ciphertext).unwrap();

        let (server_peer_bytes, server_plaintext) = server.join().unwrap();
        assert_eq!(server_peer_bytes, alice_public_bytes);
        assert_eq!(server_plaintext, b"from-client");
    }
}
