use anyhow::Result;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::prelude::*;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use std::io::stdout;

pub(crate) struct PickerItem {
    pub primary: String,
    pub secondary: String,
}

pub(crate) fn run_picker(title: &str, help: &str, items: &[PickerItem]) -> Result<usize> {
    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut state = ListState::default().with_selected(Some(0));

    loop {
        terminal.draw(|frame| {
            let areas =
                Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).split(frame.area());

            frame.render_widget(Paragraph::new(help.to_string()), areas[0]);

            let rendered_items: Vec<ListItem> = items
                .iter()
                .map(|item| {
                    ListItem::new(vec![
                        Line::from(item.primary.clone()),
                        Line::from(item.secondary.clone()),
                    ])
                })
                .collect();

            let list = List::new(rendered_items)
                .block(Block::default().borders(Borders::ALL).title(title))
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
                .highlight_symbol("› ");

            frame.render_stateful_widget(list, areas[1], &mut state);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            let selected = state.selected().unwrap_or(0);
            match key.code {
                KeyCode::Up => {
                    state.select(Some(selected.saturating_sub(1)));
                }
                KeyCode::Down => {
                    state.select(Some((selected + 1).min(items.len().saturating_sub(1))));
                }
                KeyCode::Enter => return Ok(selected),
                KeyCode::Esc | KeyCode::Char('q') => anyhow::bail!("Selection cancelled"),
                _ => {}
            }
        }
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    }
}
