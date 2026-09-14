//! Rendering for all TUI screens.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::app::{AddPeerFocus, App, ConnectFocus, Screen, MENU_ITEMS};
use crate::chat::{ChatLine, ChatSession};

pub fn draw(f: &mut Frame, app: &App) {
    match &app.screen {
        Screen::Menu { selected } => draw_menu(f, app, *selected),
        Screen::Connect {
            host,
            port,
            focus,
            error,
        } => draw_connect(f, *focus, host, port, error.as_deref()),
        Screen::Connecting { status, .. } => draw_status(f, "Connecting", status),
        Screen::Listen {
            port,
            listener,
            status,
            error,
        } => draw_listen(
            f,
            port,
            listener.is_some(),
            status.as_deref(),
            error.as_deref(),
        ),
        Screen::Peers { peers, selected } => draw_peers(f, peers, *selected),
        Screen::AddPeer {
            address,
            fingerprint,
            focus,
            error,
        } => draw_add_peer(f, *focus, address, fingerprint, error.as_deref()),
        Screen::Notice { text } => draw_notice(f, text),
        Screen::Mismatch {
            peer_id,
            expected_short,
            got_short,
            ..
        } => draw_mismatch(f, peer_id, expected_short, got_short),
        Screen::Chat(session) => draw_chat(f, session),
    }
}

fn draw_menu(f: &mut Frame, app: &App, selected: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(f.area());

    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "DirectMessages",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("my fingerprint: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.my_fingerprint.as_str(),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" DirectMessages "),
    );
    f.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = MENU_ITEMS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(format!("  {}. {label}", i + 1)).style(style)
        })
        .collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(" Menu "));
    f.render_widget(list, chunks[1]);

    let footer = Paragraph::new("↑/↓ select · Enter choose · 1-5 shortcut · q/Esc quit")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    f.render_widget(footer, chunks[2]);
}

fn draw_connect(f: &mut Frame, focus: ConnectFocus, host: &str, port: &str, error: Option<&str>) {
    let area = centered(f.area(), 60, 60);
    f.render_widget(Clear, area);

    let mut lines = vec![
        Line::from(Span::styled(
            "Connect to a peer",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        field_line("host", host, focus == ConnectFocus::Host),
        field_line("port", port, focus == ConnectFocus::Port),
        Line::from(""),
        Line::from(Span::styled(
            "Tab/↑/↓ switch field · Enter connect · Esc back",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    if let Some(e) = error {
        lines.push(Line::from(Span::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        )));
    }

    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Connect "));
    f.render_widget(p, area);
}

fn draw_status(f: &mut Frame, title: &str, status: &str) {
    let area = centered(f.area(), 60, 40);
    f.render_widget(Clear, area);
    let p = Paragraph::new(vec![
        Line::from(Span::styled(status.to_string(), Style::default())),
        Line::from(""),
        Line::from(Span::styled(
            "Esc cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {title} ")),
    )
    .alignment(Alignment::Center);
    f.render_widget(p, area);
}

fn draw_listen(
    f: &mut Frame,
    port: &str,
    listening: bool,
    status: Option<&str>,
    error: Option<&str>,
) {
    let area = centered(f.area(), 60, 60);
    f.render_widget(Clear, area);

    let mut lines = vec![
        Line::from(Span::styled(
            "Listen for a connection",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    if listening {
        if let Some(s) = status {
            lines.push(Line::from(Span::styled(
                s.to_string(),
                Style::default().fg(Color::Green),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Esc cancel",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        lines.push(field_line("port", port, true));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Enter start · Esc back",
            Style::default().fg(Color::DarkGray),
        )));
        if let Some(e) = error {
            lines.push(Line::from(Span::styled(
                format!("error: {e}"),
                Style::default().fg(Color::Red),
            )));
        }
    }

    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Listen "));
    f.render_widget(p, area);
}

fn draw_peers(f: &mut Frame, peers: &[(String, String)], selected: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(f.area());

    let items: Vec<ListItem> = if peers.is_empty() {
        vec![ListItem::new("  (no trusted peers yet — press 'a' to add)")]
    } else {
        peers
            .iter()
            .enumerate()
            .map(|(i, (addr, fp))| {
                let style = if i == selected {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else {
                    Style::default()
                };
                let short = format!("fp:{}", &fp[..fp.len().min(16)]);
                ListItem::new(format!("  {addr:32}  {short}")).style(style)
            })
            .collect()
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Trusted peers "),
    );
    f.render_widget(list, chunks[0]);

    let footer = Paragraph::new("↑/↓ select · a add · r remove · Esc back")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    f.render_widget(footer, chunks[1]);
}

fn draw_add_peer(
    f: &mut Frame,
    focus: AddPeerFocus,
    address: &str,
    fingerprint: &str,
    error: Option<&str>,
) {
    let area = centered(f.area(), 70, 70);
    f.render_widget(Clear, area);

    let addr = if focus == AddPeerFocus::Address {
        format!("{address}|")
    } else {
        address.to_string()
    };
    let fp = if focus == AddPeerFocus::Fingerprint {
        format!("{fingerprint}|")
    } else {
        fingerprint.to_string()
    };

    let mut lines = vec![
        Line::from(Span::styled(
            "Add a trusted peer",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  address:    ", Style::default().fg(Color::Cyan)),
            Span::styled(addr, Style::default()),
        ]),
        Line::from(vec![
            Span::styled("  fingerprint:", Style::default().fg(Color::Cyan)),
            Span::styled(fp, Style::default()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Tab/↑/↓ switch field · Enter save · Esc back",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    if let Some(e) = error {
        lines.push(Line::from(Span::styled(
            format!("error: {e}"),
            Style::default().fg(Color::Red),
        )));
    }

    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Add peer "));
    f.render_widget(p, area);
}

fn draw_notice(f: &mut Frame, text: &str) {
    let area = centered(f.area(), 70, 50);
    f.render_widget(Clear, area);
    let content = format!("{text}\n\n(press any key to continue)");
    let p = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Notice ")
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_mismatch(f: &mut Frame, peer_id: &str, expected_short: &str, got_short: &str) {
    let area = centered(f.area(), 70, 70);
    f.render_widget(Clear, area);

    let content = vec![
        Line::from(Span::styled(
            "SECURITY WARNING",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "The fingerprint of peer {peer_id} changed since the"
        )),
        Line::from("last connection. Either the peer regenerated its"),
        Line::from("keypair, or someone is intercepting the connection"),
        Line::from("(man-in-the-middle)."),
        Line::from(""),
        Line::from(vec![
            Span::styled("  expected: ", Style::default().fg(Color::DarkGray)),
            Span::styled(expected_short.to_string(), Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::styled("  got:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(got_short.to_string(), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from("Verify the new fingerprint with the peer over a"),
        Line::from("different channel (in person, by phone, ...)."),
        Line::from(""),
        Line::from(Span::styled(
            "U trust the new key and continue · any other key abort",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    let p = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Fingerprint mismatch ")
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_chat(f: &mut Frame, session: &ChatSession) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(f.area());

    let history_height = chunks[0].height.saturating_sub(2) as usize;
    let lines = chat_lines(session, history_height);

    let title = if session.ended {
        format!(
            " Chat with {} — disconnected (Esc to leave) ",
            session.peer_short_fp
        )
    } else {
        format!(" Chat with {} ", session.peer_short_fp)
    };
    let list = List::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(list, chunks[0]);

    let input_display = if session.ended {
        session.input.clone()
    } else {
        format!("{}|", session.input)
    };
    let input = Paragraph::new(format!("> {input_display}"))
        .block(Block::default().borders(Borders::ALL).title(" Message "));
    f.render_widget(input, chunks[1]);
}

fn chat_lines(session: &ChatSession, visible: usize) -> Vec<ListItem<'_>> {
    let total = session.history.len();
    let scroll = session.scroll.min(total);
    let end = total - scroll;
    let start = end.saturating_sub(visible);

    session.history[start..end]
        .iter()
        .map(|line| match line {
            ChatLine::Me(t) => {
                ListItem::new(format!("  [me]   {t}")).style(Style::default().fg(Color::Green))
            }
            ChatLine::Peer(t) => {
                ListItem::new(format!("  [peer] {t}")).style(Style::default().fg(Color::Cyan))
            }
            ChatLine::System(t) => {
                ListItem::new(format!("  · {t}")).style(Style::default().fg(Color::DarkGray))
            }
        })
        .collect()
}

fn field_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    let value = if focused {
        format!("{value}|")
    } else {
        value.to_string()
    };
    Line::from(vec![
        Span::styled(format!("  {label:4} "), Style::default().fg(Color::Cyan)),
        Span::styled(value, Style::default()),
    ])
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1]);
    horizontal[1]
}
