use std::io::{self, Stdout};

use ansi_to_tui::IntoText;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::Text,
    widgets::{Block, List, ListItem, ListState, Paragraph},
};
use rest_api_types::models::{ClientPendingFile, PendingFile};

use crate::{error::ClientCliError, utils::bishop_art};

// Restores the terminal state when dropped, so panics and early returns
// cannot leave the user in raw mode or the alternate screen.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    files: &[PendingFile],
    list_state: &mut ListState,
) -> io::Result<()> {
    let count = files.len();
    let index = list_state.selected().unwrap_or(0);
    let mut art_text: Text<'static> = bishop_art(files[index].digest())
        .into_text()
        .unwrap_or_default();
    art_text.push_line(String::new());
    art_text.push_line(files[index].digest().to_string());

    terminal.draw(|f| {
        let outer = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(f.area());
        let panels = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(outer[0]);

        let items: Vec<ListItem> = files.iter().map(|pf| ListItem::new(pf.path())).collect();
        let list = List::new(items)
            .block(Block::bordered().title(format!(" Pending files ({}) ", count)))
            .highlight_symbol("> ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        f.render_stateful_widget(list, panels[0], list_state);

        let art_para =
            Paragraph::new(art_text).block(Block::bordered().title(" Bishop fingerprint "));
        f.render_widget(art_para, panels[1]);

        let hints = Paragraph::new("  ↑/k prev   ↓/j next   enter confirm   esc cancel");
        f.render_widget(hints, outer[1]);
    })?;
    Ok(())
}

pub fn select_pending_file(files: Vec<PendingFile>) -> Result<ClientPendingFile, ClientCliError> {
    if files.is_empty() {
        return Err(ClientCliError::NoPendingSignature);
    }

    let count = files.len();

    execute!(io::stdout(), EnterAlternateScreen)
        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
    let _guard = TerminalGuard;
    terminal::enable_raw_mode().map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    let mut list_state = ListState::default();
    list_state.select(Some(0));

    draw(&mut terminal, &files, &mut list_state)
        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    loop {
        match event::read() {
            Ok(Event::Key(key)) => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    let i = list_state.selected().unwrap_or(0);
                    list_state.select(Some((i + count - 1) % count));
                    draw(&mut terminal, &files, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let i = list_state.selected().unwrap_or(0);
                    list_state.select(Some((i + 1) % count));
                    draw(&mut terminal, &files, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Enter => {
                    let i = list_state.selected().unwrap_or(0);
                    return Ok(files[i].unseal());
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    return Err(ClientCliError::InvalidInput(
                        "Selection cancelled or failed: no path to sign was provided".into(),
                    ));
                }
                _ => {}
            },
            Ok(_) => {}
            Err(e) => return Err(ClientCliError::InvalidInput(e.to_string())),
        }
    }
}
