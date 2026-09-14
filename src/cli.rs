//! Command-line interface definitions (clap).

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "directmessages",
    version,
    about = "Encrypted peer-to-peer messenger over TCP (X25519 + ChaCha20-Poly1305)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Wait for an incoming connection on PORT, then chat
    Listen {
        /// Port to listen on
        #[arg(value_name = "PORT")]
        port: u16,
    },
    /// Connect to a peer at IP:PORT, then chat
    Connect {
        /// Remote IP address or hostname
        #[arg(value_name = "IP")]
        ip: String,
        /// Remote port
        #[arg(value_name = "PORT")]
        port: u16,
    },
    /// Generate a new keypair (overwrites any existing one)
    Keygen,
    /// Print this node's public-key fingerprint
    Fingerprint,
    /// Manually pin a peer's fingerprint for an address
    Trust {
        /// The peer's full 64-hex-character fingerprint
        #[arg(value_name = "FINGERPRINT")]
        fingerprint: String,
        /// Address to pin it to, as HOST:PORT
        #[arg(value_name = "HOST:PORT")]
        address: String,
    },
}
