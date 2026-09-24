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

/// Whether a person is at the keyboard to answer a picker.
///
/// Both ends, deliberately. A picker draws on stdout and reads keys from
/// stdin, so either one redirected means somebody is piping this command and
/// a raw-mode screen would hang their pipe rather than ask them anything.
///
/// This is the terminal half of the question only. Whether the *caller* wants
/// to prompt at all — `--output json`, `--yes` — is theirs to decide, because
/// this module cannot see those flags. See [`crate::commands::can_prompt`].
pub(crate) fn terminal_is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Let the person choose one of `items`, or explain why they cannot.
///
/// # Refusing rather than hanging
///
/// `enable_raw_mode` against a redirected stdin fails with an ioctl error that
/// names nothing a caller can act on, and with stdin redirected but stdout a
/// terminal it waits for a keypress that never arrives. Both are reachable the
/// moment a script or an agent runs a command whose argument was optional.
///
/// So a non-interactive run is answered with the candidates and how to name
/// one, which is what lets an unattended caller retry on its own instead of
/// failing twice.
pub(crate) fn run_picker(title: &str, help: &str, items: &[PickerItem]) -> Result<usize> {
    if !terminal_is_interactive() {
        anyhow::bail!(
            "{title}: {} candidates and no terminal to choose on. Name one:\n{}",
            items.len(),
            items
                .iter()
                .map(|item| format!("  {}  {}", item.primary, item.secondary))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<PickerItem> {
        vec![
            PickerItem {
                primary: "sandbox-1c165e1b8dc".into(),
                secondary: "kache-ci-sim2 · ready".into(),
            },
            PickerItem {
                primary: "sandbox-e42a8a520cc".into(),
                secondary: "nixiso · releasing".into(),
            },
        ]
    }

    /// The property this exists for: a run with no terminal is refused before
    /// raw mode, and refused with something a caller can act on.
    ///
    /// Under `cargo test` stdout is captured, so this is the non-interactive
    /// path by construction — the same reason an agent or a pipe reaches it.
    #[test]
    fn a_run_without_a_terminal_is_told_how_to_choose() {
        let error = run_picker("Select a lease to open a desktop on", "help", &items())
            .expect_err("a captured stdout is not a terminal");
        let message = error.to_string();

        assert!(
            message.contains("Select a lease to open a desktop on"),
            "the refusal names the choice being made: {message}"
        );
        for item in items() {
            assert!(
                message.contains(&item.primary),
                "every candidate is named so a caller can pass one: {message}"
            );
            assert!(message.contains(&item.secondary), "{message}");
        }
    }

    /// An ioctl error names nothing to act on. This is what replaced it, so
    /// the replacement must not read like one.
    #[test]
    fn the_refusal_is_not_a_terminal_error() {
        let message = run_picker("Select a lease", "help", &items())
            .expect_err("not a terminal")
            .to_string()
            .to_lowercase();

        for noise in ["ioctl", "raw mode", "os error"] {
            assert!(
                !message.contains(noise),
                "refusal leaked a terminal-layer detail ({noise}): {message}"
            );
        }
    }
}
