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
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
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

fn filtered_indices(files: &[PendingFile], filter: &str) -> Vec<usize> {
    if filter.is_empty() {
        return (0..files.len()).collect();
    }
    let lower = filter.to_lowercase();
    files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.path().to_lowercase().contains(&lower))
        .map(|(i, _)| i)
        .collect()
}

fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    files: &[PendingFile],
    filter: &str,
    list_state: &mut ListState,
) -> io::Result<()> {
    let indices = filtered_indices(files, filter);
    let file_index = indices.get(list_state.selected().unwrap_or(0)).copied();

    terminal.draw(|f| {
        let outer = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(f.area());
        let panels = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(outer[0]);

        let left = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(panels[0]);

        let filter_para = Paragraph::new(filter).block(Block::bordered().title(" Filter "));
        f.render_widget(filter_para, left[0]);

        let items: Vec<ListItem> = indices
            .iter()
            .map(|&i| ListItem::new(files[i].path()))
            .collect();
        let list_title = format!(" Pending files ({}/{}) ", indices.len(), files.len());
        let list = List::new(items)
            .block(Block::bordered().title(list_title))
            .highlight_symbol("> ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        f.render_stateful_widget(list, left[1], list_state);

        let art_text: Text<'static> = if let Some(idx) = file_index {
            let mut t = bishop_art(files[idx].digest())
                .into_text()
                .unwrap_or_default();
            t.push_line(String::new());
            t.push_line(files[idx].digest().to_string());
            t
        } else {
            Text::from("No matches")
        };
        let art_para = Paragraph::new(art_text)
            .block(Block::bordered().title(" Bishop fingerprint "))
            .wrap(Wrap { trim: false });
        f.render_widget(art_para, panels[1]);

        let hints =
            Paragraph::new("  type to filter   ↑/↓ navigate   enter confirm   esc clear/cancel");
        f.render_widget(hints, outer[1]);
    })?;
    Ok(())
}

pub fn select_pending_file(files: Vec<PendingFile>) -> Result<ClientPendingFile, ClientCliError> {
    if files.is_empty() {
        return Err(ClientCliError::NoPendingSignature);
    }

    execute!(io::stdout(), EnterAlternateScreen)
        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
    let _guard = TerminalGuard;
    terminal::enable_raw_mode().map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    let mut filter = String::new();
    let mut list_state = ListState::default();
    list_state.select(Some(0));

    draw(&mut terminal, &files, &filter, &mut list_state)
        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    loop {
        match event::read() {
            Ok(Event::Key(key)) => match key.code {
                KeyCode::Up => {
                    let indices = filtered_indices(&files, &filter);
                    let count = indices.len();
                    if count > 0 {
                        let i = list_state.selected().unwrap_or(0);
                        list_state.select(Some((i + count - 1) % count));
                    }
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Down => {
                    let indices = filtered_indices(&files, &filter);
                    let count = indices.len();
                    if count > 0 {
                        let i = list_state.selected().unwrap_or(0);
                        list_state.select(Some((i + 1) % count));
                    }
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Enter => {
                    let indices = filtered_indices(&files, &filter);
                    if let Some(&file_idx) = indices.get(list_state.selected().unwrap_or(0)) {
                        return Ok(files[file_idx].unseal());
                    }
                }
                KeyCode::Esc => {
                    if filter.is_empty() {
                        return Err(ClientCliError::InvalidInput(
                            "Selection cancelled or failed: no path to sign was provided".into(),
                        ));
                    }
                    filter.clear();
                    list_state.select(Some(0));
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Backspace => {
                    filter.pop();
                    list_state.select(Some(0));
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Char(c) => {
                    filter.push(c);
                    list_state.select(Some(0));
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                _ => {}
            },
            Ok(_) => {}
            Err(e) => return Err(ClientCliError::InvalidInput(e.to_string())),
        }
    }
}
