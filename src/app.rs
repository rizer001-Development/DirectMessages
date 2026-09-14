//! Application state machine and event loop for the TUI.

use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{unbounded, Receiver};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

use crate::chat::ChatSession;
use crate::crypto::{self, Identity};
use crate::protocol;
use crate::state::{self, TrustDecision};
use crate::ui;

const TICK: Duration = Duration::from_millis(50);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) const MENU_ITEMS: [&str; 5] = [
    "Connect to peer",
    "Listen for connection",
    "Manage peers",
    "Regenerate keypair",
    "Quit",
];

/// The top-level application state.
pub(crate) struct App {
    identity: Arc<Identity>,
    pub my_fingerprint: String,
    pub screen: Screen,
    should_quit: bool,
}

/// The current screen of the TUI.
pub(crate) enum Screen {
    Menu {
        selected: usize,
    },
    Connect {
        host: String,
        port: String,
        focus: ConnectFocus,
        error: Option<String>,
    },
    Connecting {
        status: String,
        rx: Option<Receiver<Result<Outcome, String>>>,
    },
    Listen {
        port: String,
        listener: Option<TcpListener>,
        status: Option<String>,
        error: Option<String>,
    },
    Peers {
        peers: Vec<(String, String)>,
        selected: usize,
    },
    AddPeer {
        address: String,
        fingerprint: String,
        focus: AddPeerFocus,
        error: Option<String>,
    },
    Notice {
        text: String,
    },
    /// A stored fingerprint no longer matches the peer's live key. The user
    /// must either confirm the new key (re-pin and continue) or abort.
    Mismatch {
        peer_id: String,
        expected_short: String,
        got_short: String,
        /// Full handshake outcome, kept so "U" can continue into the chat.
        outcome: Option<Outcome>,
    },
    Chat(ChatSession),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectFocus {
    Host,
    Port,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddPeerFocus {
    Address,
    Fingerprint,
}

/// The result of establishing a connection and completing the handshake.
pub(crate) struct Outcome {
    stream: TcpStream,
    sender: crypto::SessionSender,
    receiver: crypto::SessionReceiver,
    peer_fingerprint: String,
    peer_id: String,
}

impl App {
    pub fn new() -> Result<Self> {
        let identity = Arc::new(state::load_or_create_keypair()?);
        let my_fingerprint = crypto::fingerprint(&identity.public);
        Ok(App {
            identity,
            my_fingerprint,
            screen: Screen::Menu { selected: 0 },
            should_quit: false,
        })
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.should_quit {
            terminal.draw(|f| ui::draw(f, self))?;
            if event::poll(TICK)? {
                if let Event::Key(key) = event::read()? {
                    self.on_key(key);
                }
            }
            self.tick();
        }
        if let Screen::Chat(session) = &mut self.screen {
            session.close();
        }
        Ok(())
    }

    /// Drain asynchronous channels and advance the state machine.
    fn tick(&mut self) {
        if let Screen::Chat(session) = &mut self.screen {
            session.drain_events();
        }

        let next: Option<Screen> = match &mut self.screen {
            Screen::Connecting { rx, .. } => match rx.as_mut().and_then(|r| r.try_recv().ok()) {
                Some(Ok(outcome)) => match build_chat_screen(outcome) {
                    Ok(s) => Some(s),
                    Err(e) => Some(notice(format!("failed to start chat: {e}"))),
                },
                Some(Err(e)) => Some(notice(format!("connection failed: {e}"))),
                None => None,
            },
            Screen::Listen {
                listener: Some(l), ..
            } => match l.accept() {
                Ok((stream, addr)) => {
                    stream.set_nonblocking(false).ok();
                    match outcome_from_handshake(
                        self.identity.as_ref(),
                        stream,
                        false,
                        addr.ip().to_string(),
                    ) {
                        Ok(outcome) => match build_chat_screen(outcome) {
                            Ok(s) => Some(s),
                            Err(e) => Some(notice(format!("failed to start chat: {e}"))),
                        },
                        Err(e) => Some(notice(format!("handshake failed: {e}"))),
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                Err(e) => Some(notice(format!("listen failed: {e}"))),
            },
            Screen::Listen { listener: None, .. } => None,
            _ => None,
        };

        if let Some(screen) = next {
            self.screen = screen;
        }
    }

    fn on_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return;
        }

        let mut next: Option<Screen> = None;

        match &mut self.screen {
            Screen::Menu { selected } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => *selected = (*selected + 1).min(MENU_ITEMS.len() - 1),
                KeyCode::Enter => {
                    if let Some(s) = menu_action(
                        *selected,
                        &mut self.identity,
                        &mut self.my_fingerprint,
                        &mut self.should_quit,
                    ) {
                        next = Some(s);
                    }
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    if let Some(n) = c.to_digit(10) {
                        let n = n as usize;
                        if (1..=MENU_ITEMS.len()).contains(&n) {
                            if let Some(s) = menu_action(
                                n - 1,
                                &mut self.identity,
                                &mut self.my_fingerprint,
                                &mut self.should_quit,
                            ) {
                                next = Some(s);
                            }
                        }
                    }
                }
                _ => {}
            },
            Screen::Connect {
                host,
                port,
                focus,
                error,
            } => match key.code {
                KeyCode::Esc => next = Some(Screen::Menu { selected: 0 }),
                KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                    *focus = match focus {
                        ConnectFocus::Host => ConnectFocus::Port,
                        ConnectFocus::Port => ConnectFocus::Host,
                    }
                }
                KeyCode::Enter => {
                    if *focus == ConnectFocus::Host {
                        *focus = ConnectFocus::Port;
                    } else {
                        match port.parse::<u16>() {
                            Ok(p) if !host.is_empty() => {
                                let (_, rx) =
                                    spawn_connect(Arc::clone(&self.identity), host.clone(), p);
                                next = Some(Screen::Connecting {
                                    status: format!("connecting to {host}:{p}..."),
                                    rx: Some(rx),
                                });
                            }
                            _ => *error = Some("enter a valid host and port (1-65535)".to_string()),
                        }
                    }
                }
                KeyCode::Backspace => {
                    match focus {
                        ConnectFocus::Host => {
                            host.pop();
                        }
                        ConnectFocus::Port => {
                            port.pop();
                        }
                    }
                    *error = None;
                }
                KeyCode::Char(c) => {
                    match focus {
                        ConnectFocus::Host => host.push(c),
                        ConnectFocus::Port => {
                            if c.is_ascii_digit() {
                                port.push(c);
                            }
                        }
                    }
                    *error = None;
                }
                _ => {}
            },
            Screen::Connecting { .. } => {
                if key.code == KeyCode::Esc {
                    next = Some(Screen::Menu { selected: 0 });
                }
            }
            Screen::Listen {
                port,
                listener,
                status,
                error,
            } => {
                if listener.is_some() {
                    if key.code == KeyCode::Esc {
                        next = Some(Screen::Menu { selected: 0 });
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => next = Some(Screen::Menu { selected: 0 }),
                        KeyCode::Enter => match port.parse::<u16>() {
                            Ok(p) => match TcpListener::bind(("0.0.0.0", p)) {
                                Ok(l) => {
                                    l.set_nonblocking(true).ok();
                                    *status = Some(format!(
                                        "listening on 0.0.0.0:{p} — waiting for a connection..."
                                    ));
                                    *listener = Some(l);
                                    *error = None;
                                }
                                Err(e) => *error = Some(format!("bind failed: {e}")),
                            },
                            Err(_) => *error = Some("enter a valid port (1-65535)".to_string()),
                        },
                        KeyCode::Backspace => {
                            port.pop();
                            *error = None;
                        }
                        KeyCode::Char(c) => {
                            if c.is_ascii_digit() {
                                port.push(c);
                            }
                            *error = None;
                        }
                        _ => {}
                    }
                }
            }
            Screen::Peers { peers, selected } => match key.code {
                KeyCode::Esc => next = Some(Screen::Menu { selected: 0 }),
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => {
                    if !peers.is_empty() {
                        *selected = (*selected + 1).min(peers.len() - 1);
                    }
                }
                KeyCode::Char('r') | KeyCode::Char('d') => {
                    if let Some((addr, _)) = peers.get(*selected).cloned() {
                        match state::remove_peer(&addr) {
                            Ok(()) => {
                                peers.remove(*selected);
                                *selected = if peers.is_empty() {
                                    0
                                } else {
                                    (*selected).min(peers.len() - 1)
                                };
                            }
                            Err(e) => next = Some(notice(format!("failed to remove peer: {e}"))),
                        }
                    }
                }
                KeyCode::Char('a') => {
                    next = Some(Screen::AddPeer {
                        address: String::new(),
                        fingerprint: String::new(),
                        focus: AddPeerFocus::Address,
                        error: None,
                    })
                }
                _ => {}
            },
            Screen::AddPeer {
                address,
                fingerprint,
                focus,
                error,
            } => match key.code {
                KeyCode::Esc => {
                    next = Some(Screen::Peers {
                        peers: load_peers(),
                        selected: 0,
                    })
                }
                KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                    *focus = match focus {
                        AddPeerFocus::Address => AddPeerFocus::Fingerprint,
                        AddPeerFocus::Fingerprint => AddPeerFocus::Address,
                    }
                }
                KeyCode::Enter => {
                    if *focus == AddPeerFocus::Address {
                        *focus = AddPeerFocus::Fingerprint;
                    } else {
                        let fp = fingerprint.trim().to_lowercase();
                        if address.is_empty() {
                            *error = Some("enter the peer's address (host:port)".to_string());
                        } else if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                            *error = Some("fingerprint must be 64 hex characters".to_string());
                        } else {
                            match state::pin_peer(address, &fp) {
                                Ok(()) => {
                                    next = Some(Screen::Peers {
                                        peers: load_peers(),
                                        selected: 0,
                                    })
                                }
                                Err(e) => *error = Some(format!("failed to pin peer: {e}")),
                            }
                        }
                    }
                }
                KeyCode::Backspace => {
                    match focus {
                        AddPeerFocus::Address => {
                            address.pop();
                        }
                        AddPeerFocus::Fingerprint => {
                            fingerprint.pop();
                        }
                    }
                    *error = None;
                }
                KeyCode::Char(c) => match focus {
                    AddPeerFocus::Address => address.push(c),
                    AddPeerFocus::Fingerprint => {
                        if c.is_ascii_hexdigit() {
                            fingerprint.push(c.to_ascii_lowercase());
                        }
                    }
                },
                _ => {}
            },
            Screen::Notice { .. } => {
                next = Some(Screen::Menu { selected: 0 });
            }
            Screen::Mismatch {
                peer_id,
                outcome,
                got_short,
                ..
            } => {
                // Explicit confirmation re-pins the peer and continues into
                // the chat; anything else aborts back to the menu.
                if key.code == KeyCode::Char('u') || key.code == KeyCode::Char('U') {
                    if let Some(outcome) = outcome.take() {
                        let full_fp = outcome.peer_fingerprint.clone();
                        match state::pin_peer(&outcome.peer_id, &full_fp) {
                            Ok(()) => match build_chat_screen(outcome) {
                                Ok(s) => next = Some(s),
                                Err(e) => next = Some(notice(format!("failed to start chat: {e}"))),
                            },
                            Err(e) => next = Some(notice(format!("failed to update peer: {e}"))),
                        }
                    } else {
                        next = Some(Screen::Menu { selected: 0 });
                    }
                } else {
                    let _ = (peer_id, got_short);
                    next = Some(Screen::Menu { selected: 0 });
                }
            }
            Screen::Chat(session) => {
                if session.ended {
                    if key.code == KeyCode::Esc || key.code == KeyCode::Enter {
                        session.close();
                        next = Some(Screen::Menu { selected: 0 });
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => {
                            session.close();
                            next = Some(Screen::Menu { selected: 0 });
                        }
                        KeyCode::Enter => {
                            let cmd = session.input.trim();
                            if cmd == "/quit" || cmd == "/exit" {
                                session.close();
                                next = Some(Screen::Menu { selected: 0 });
                            } else if let Err(e) = session.send() {
                                session.push_system(format!("send failed: {e}"));
                            }
                        }
                        KeyCode::Backspace => {
                            session.input.pop();
                        }
                        KeyCode::Char(c) => {
                            session.input.push(c);
                        }
                        KeyCode::Up => session.scroll = session.scroll.saturating_add(1),
                        KeyCode::Down => session.scroll = session.scroll.saturating_sub(1),
                        KeyCode::PageUp => session.scroll = session.scroll.saturating_add(10),
                        KeyCode::PageDown => session.scroll = session.scroll.saturating_sub(10),
                        _ => {}
                    }
                }
            }
        }

        if let Some(screen) = next {
            self.screen = screen;
        }
    }
}

fn notice(text: impl Into<String>) -> Screen {
    Screen::Notice { text: text.into() }
}

fn load_peers() -> Vec<(String, String)> {
    state::list_peers().unwrap_or_default()
}

fn menu_action(
    selected: usize,
    identity: &mut Arc<Identity>,
    my_fingerprint: &mut String,
    should_quit: &mut bool,
) -> Option<Screen> {
    match selected {
        0 => Some(Screen::Connect {
            host: String::new(),
            port: String::new(),
            focus: ConnectFocus::Host,
            error: None,
        }),
        1 => Some(Screen::Listen {
            port: String::new(),
            listener: None,
            status: None,
            error: None,
        }),
        2 => Some(Screen::Peers {
            peers: load_peers(),
            selected: 0,
        }),
        3 => match state::generate_and_save() {
            Ok(id) => {
                let fp = crypto::fingerprint(&id.public);
                *my_fingerprint = fp.clone();
                *identity = Arc::new(id);
                Some(notice(format!("new keypair generated\nfingerprint: {fp}")))
            }
            Err(e) => Some(notice(format!("keygen failed: {e}"))),
        },
        4 => {
            *should_quit = true;
            None
        }
        _ => None,
    }
}

fn outcome_from_handshake(
    identity: &Identity,
    mut stream: TcpStream,
    is_initiator: bool,
    peer_id: String,
) -> Result<Outcome> {
    let (sender, receiver, peer_public) =
        protocol::perform_handshake(&mut stream, is_initiator, identity)?;
    let peer_fingerprint = crypto::fingerprint(&peer_public);
    Ok(Outcome {
        stream,
        sender,
        receiver,
        peer_fingerprint,
        peer_id,
    })
}

fn short_fp(fp: &str) -> String {
    format!("fp:{}", &fp[..fp.len().min(16)])
}

fn build_chat_screen(outcome: Outcome) -> Result<Screen> {
    let peer_short = short_fp(&outcome.peer_fingerprint);
    let short = peer_short.clone();
    match state::check_peer(&outcome.peer_id, &outcome.peer_fingerprint)? {
        TrustDecision::New => {
            state::pin_peer(&outcome.peer_id, &outcome.peer_fingerprint)?;
            let mut session =
                ChatSession::new(outcome.stream, outcome.sender, outcome.receiver, peer_short)?;
            session.push_system(format!(
                "new peer — verify this fingerprint out-of-band: {short}"
            ));
            Ok(Screen::Chat(session))
        }
        TrustDecision::Verified => {
            let session =
                ChatSession::new(outcome.stream, outcome.sender, outcome.receiver, peer_short)?;
            Ok(Screen::Chat(session))
        }
        TrustDecision::Mismatch { expected } => Ok(Screen::Mismatch {
            peer_id: outcome.peer_id.clone(),
            expected_short: short_fp(&expected),
            got_short: short_fp(&outcome.peer_fingerprint),
            outcome: Some(outcome),
        }),
    }
}

fn spawn_connect(
    identity: Arc<Identity>,
    host: String,
    port: u16,
) -> (JoinHandle<()>, Receiver<Result<Outcome, String>>) {
    let (tx, rx) = unbounded();
    let handle = thread::spawn(move || {
        let result = connect_outcome(identity.as_ref(), &host, port);
        let _ = tx.send(result.map_err(|e| format!("{e:#}")));
    });
    (handle, rx)
}

fn connect_outcome(identity: &Identity, host: &str, port: u16) -> Result<Outcome> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {host}:{port}"))?
        .collect();

    let mut last_err = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                return outcome_from_handshake(identity, stream, true, format!("{host}:{port}"));
            }
            Err(e) => last_err = Some(e),
        }
    }

    Err(anyhow!(
        "connect to {host}:{port} failed: {}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}
