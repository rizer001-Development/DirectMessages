//! Interactive chat loop: a sending thread (stdin) and a receiving thread
//! (socket), coordinated so either side can end the conversation.

use std::io::{self, BufRead, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;

use anyhow::{Context, Result};
use crossbeam_channel::unbounded;

use crate::crypto::{SessionReceiver, SessionSender};
use crate::protocol::{read_frame, write_frame};

/// Run the interactive chat until either side quits or disconnects.
pub fn run_chat(
    stream: TcpStream,
    mut sender: SessionSender,
    mut receiver: SessionReceiver,
) -> Result<()> {
    let mut write_stream = stream
        .try_clone()
        .context("failed to clone stream for reading")?;
    let mut read_stream = stream;

    let (tx, rx) = unbounded::<()>();

    // Receiving thread: read frames, decrypt, print.
    let tx_recv = tx.clone();
    let recv_handle = thread::spawn(move || {
        loop {
            match read_frame(&mut read_stream) {
                Ok(frame) => match receiver.decrypt(&frame) {
                    Ok(plain) => {
                        print!("\r[peer] {}\n> ", String::from_utf8_lossy(&plain));
                        io::stdout().flush().ok();
                    }
                    Err(e) => {
                        eprintln!("\rdecrypt failed: {e}");
                        break;
                    }
                },
                Err(e) => {
                    match e.kind() {
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
                            println!("\r[peer disconnected]");
                        }
                        _ => eprintln!("\rconnection error: {e}"),
                    }
                    break;
                }
            }
        }
        let _ = tx_recv.send(());
    });

    // Sending thread: read stdin, encrypt, send.
    let tx_send = tx.clone();
    let send_handle = thread::spawn(move || {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut line = String::new();

        print!("> ");
        io::stdout().flush().ok();

        loop {
            line.clear();
            match handle.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim_end();
                    if trimmed == "/quit" || trimmed == "/exit" {
                        break;
                    }
                    if trimmed.is_empty() {
                        print!("> ");
                        io::stdout().flush().ok();
                        continue;
                    }
                    match sender.encrypt(trimmed.as_bytes()) {
                        Ok(ciphertext) => {
                            if let Err(e) = write_frame(&mut write_stream, &ciphertext) {
                                eprintln!("\rsend failed: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("\rencrypt failed: {e}");
                            break;
                        }
                    }
                    print!("> ");
                    io::stdout().flush().ok();
                }
                Err(e) => {
                    eprintln!("\rstdin error: {e}");
                    break;
                }
            }
        }

        // Close our side of the socket so the peer sees a clean EOF.
        let _ = write_stream.shutdown(Shutdown::Both);
        let _ = tx_send.send(());
    });

    // Wait for either thread to finish, then exit (process teardown closes
    // the socket and stops the remaining thread).
    let _ = rx.recv();
    let _ = send_handle.join();
    let _ = recv_handle.join();

    Ok(())
}
