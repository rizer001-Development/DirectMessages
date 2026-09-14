//! Non-blocking chat session for the TUI: owns the write half and the sending
//! key, and runs a background thread that reads, decrypts, and forwards
//! incoming events over a channel.

use std::io;
use std::net::{Shutdown, TcpStream};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};
use crossbeam_channel::{unbounded, Receiver};

use crate::crypto::{SessionReceiver, SessionSender};
use crate::protocol::{read_frame, write_frame};

/// Events produced by the receiving thread.
pub enum ChatEvent {
    Message(String),
    Disconnected,
    Error(String),
}

/// A line in the chat history.
pub enum ChatLine {
    Me(String),
    Peer(String),
    System(String),
}

/// An active chat with a connected peer.
pub struct ChatSession {
    write_stream: TcpStream,
    sender: SessionSender,
    rx: Receiver<ChatEvent>,
    recv_handle: Option<JoinHandle<()>>,
    pub history: Vec<ChatLine>,
    pub input: String,
    /// Lines scrolled up from the bottom (0 = pinned to the latest message).
    pub scroll: usize,
    pub peer_short_fp: String,
    pub ended: bool,
}

impl ChatSession {
    pub fn new(
        stream: TcpStream,
        sender: SessionSender,
        receiver: SessionReceiver,
        peer_short_fp: String,
    ) -> Result<Self> {
        let mut read_stream = stream.try_clone().context("failed to clone stream")?;
        let (tx, rx) = unbounded::<ChatEvent>();

        let recv_handle = thread::spawn(move || {
            let mut receiver = receiver;
            loop {
                match read_frame(&mut read_stream) {
                    Ok(frame) => match receiver.decrypt(&frame) {
                        Ok(plain) => {
                            let text = String::from_utf8_lossy(&plain).into_owned();
                            if tx.send(ChatEvent::Message(text)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(ChatEvent::Error(format!("decrypt failed: {e}")));
                            break;
                        }
                    },
                    Err(e) => {
                        let event = match e.kind() {
                            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
                                ChatEvent::Disconnected
                            }
                            _ => ChatEvent::Error(format!("connection error: {e}")),
                        };
                        let _ = tx.send(event);
                        break;
                    }
                }
            }
        });

        Ok(ChatSession {
            write_stream: stream,
            sender,
            rx,
            recv_handle: Some(recv_handle),
            history: Vec::new(),
            input: String::new(),
            scroll: 0,
            peer_short_fp,
            ended: false,
        })
    }

    /// Add a system line to the history.
    pub fn push_system(&mut self, text: impl Into<String>) {
        self.history.push(ChatLine::System(text.into()));
    }

    /// Encrypt and send the current input, appending it to history.
    pub fn send(&mut self) -> Result<()> {
        let text = self.input.trim_end().to_string();
        if text.is_empty() {
            return Ok(());
        }
        let ciphertext = self.sender.encrypt(text.as_bytes())?;
        write_frame(&mut self.write_stream, &ciphertext)?;
        self.history.push(ChatLine::Me(text));
        self.input.clear();
        Ok(())
    }

    /// Drain any pending events from the receiving thread.
    pub fn drain_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                ChatEvent::Message(text) => self.history.push(ChatLine::Peer(text)),
                ChatEvent::Disconnected => {
                    self.history
                        .push(ChatLine::System("[peer disconnected]".to_string()));
                    self.ended = true;
                }
                ChatEvent::Error(e) => {
                    self.history.push(ChatLine::System(format!("error: {e}")));
                    self.ended = true;
                }
            }
        }
    }

    /// Shut down the connection and stop the receiving thread.
    pub fn close(&mut self) {
        let _ = self.write_stream.shutdown(Shutdown::Both);
        if let Some(handle) = self.recv_handle.take() {
            let _ = handle.join();
        }
    }
}
