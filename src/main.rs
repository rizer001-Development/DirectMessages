//! DirectMessages — encrypted peer-to-peer messenger over TCP.

mod chat;
mod cli;
mod crypto;
mod protocol;
mod state;

use std::net::{TcpListener, TcpStream};

use anyhow::{bail, Context, Result};
use clap::Parser;

use cli::Command;
use state::TrustDecision;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        Command::Keygen => cmd_keygen(),
        Command::Fingerprint => cmd_fingerprint(),
        Command::Trust {
            fingerprint,
            address,
        } => cmd_trust(&fingerprint, &address),
        Command::Listen { port } => cmd_listen(port),
        Command::Connect { ip, port } => cmd_connect(&ip, port),
    }
}

fn cmd_keygen() -> Result<()> {
    let identity = state::generate_and_save()?;
    println!("generated new keypair");
    println!("fingerprint: {}", state::full_fingerprint(&identity));
    Ok(())
}

fn cmd_fingerprint() -> Result<()> {
    let identity = state::load_or_create_keypair()?;
    println!("fingerprint: {}", state::full_fingerprint(&identity));
    Ok(())
}

fn cmd_trust(fingerprint: &str, address: &str) -> Result<()> {
    let fp = fingerprint.trim().to_lowercase();
    if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("fingerprint must be 64 hexadecimal characters");
    }
    state::pin_peer(address, &fp)?;
    println!("pinned {address} -> {fp}");
    Ok(())
}

fn cmd_listen(port: u16) -> Result<()> {
    let identity = state::load_or_create_keypair()?;
    let listener = TcpListener::bind(("0.0.0.0", port))
        .with_context(|| format!("failed to bind to port {port}"))?;
    println!(
        "listening on 0.0.0.0:{port} (my fingerprint: {})",
        state::display_fingerprint(&identity)
    );
    let (stream, addr) = listener.accept().context("failed to accept connection")?;
    println!("connection from {addr}");
    // Key the TOFU record by remote IP only (not the ephemeral source port)
    // so reconnects from the same host verify against the same slot.
    establish_and_chat(stream, &identity, false, &addr.ip().to_string())
}

fn cmd_connect(ip: &str, port: u16) -> Result<()> {
    let identity = state::load_or_create_keypair()?;
    let stream = TcpStream::connect((ip, port))
        .with_context(|| format!("failed to connect to {ip}:{port}"))?;
    println!(
        "connected to {ip}:{port} (my fingerprint: {})",
        state::display_fingerprint(&identity)
    );
    establish_and_chat(stream, &identity, true, &format!("{ip}:{port}"))
}

fn establish_and_chat(
    mut stream: TcpStream,
    identity: &crypto::Identity,
    is_initiator: bool,
    peer_id: &str,
) -> Result<()> {
    let (sender, receiver, peer_public) =
        protocol::perform_handshake(&mut stream, is_initiator, identity)?;
    let fp = crypto::fingerprint(&peer_public);
    let short = format!("fp:{}", &fp[..16]);

    match state::check_peer(peer_id, &fp)? {
        TrustDecision::New => {
            println!("new peer — verify this fingerprint out-of-band: {short}");
            state::pin_peer(peer_id, &fp)?;
        }
        TrustDecision::Verified => {
            println!("peer fingerprint verified: {short}");
        }
        TrustDecision::Mismatch { expected } => {
            let expected_short = format!("fp:{}", &expected[..expected.len().min(16)]);
            eprintln!(
                "SECURITY WARNING: peer fingerprint for {peer_id} changed.\n  expected: {expected_short}\n  got:      {short}\n  Possible man-in-the-middle attack. Aborting."
            );
            return Ok(());
        }
    }

    println!("secure channel established. type /quit to exit.");
    chat::run_chat(stream, sender, receiver)
}
