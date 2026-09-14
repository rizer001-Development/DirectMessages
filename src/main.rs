//! DirectMessages — encrypted peer-to-peer messenger (TUI).

mod app;
mod chat;
mod crypto;
mod protocol;
mod state;
mod ui;

use anyhow::Result;

fn main() -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run(&mut terminal);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let mut app = app::App::new()?;
    app.run(terminal)
}
