use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::*;
use std::io::stdout;
use std::time::Duration;

use super::config::{AuthMode, CliConfig};

// ── Field definitions ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum FieldKind {
    Text,
    Select,
    Password,
}

#[derive(Debug, Clone)]
struct FormField {
    label: &'static str,
    kind: FieldKind,
    value: String,
    options: Vec<&'static str>,
    default_hint: &'static str,
    is_password: bool,
    /// (field_index, required_value) — only show when fields[index].value == required_value
    visible_when: Option<(usize, &'static str)>,
}

impl FormField {
    fn display_value(&self) -> String {
        if self.value.is_empty() {
            self.default_hint.to_string()
        } else if self.is_password {
            "*".repeat(self.value.len().min(20))
        } else {
            self.value.clone()
        }
    }

    fn is_placeholder(&self) -> bool {
        self.value.is_empty()
    }

    fn visible(&self, fields: &[FormField]) -> bool {
        match self.visible_when {
            Some((idx, val)) => fields.get(idx).map(|f| f.value == val).unwrap_or(true),
            None => true,
        }
    }
}

// ── Editor state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum Mode {
    Navigate,
    Editing,
    ConfirmQuit,
    ConfirmSave,
}

struct EditorState {
    fields: Vec<FormField>,
    cursor: usize,
    mode: Mode,
    edit_buffer: String,
    edit_cursor: usize,
    dirty: bool,
    status: Option<String>,
}

fn build_fields(config: &CliConfig) -> Vec<FormField> {
    let auth_str = match config.auth {
        AuthMode::None => "none",
        AuthMode::Token => "token",
        AuthMode::Oidc => "oidc",
    };

    vec![
        FormField {
            label: "Endpoint",
            kind: FieldKind::Text,
            value: config.endpoint.clone().unwrap_or_default(),
            options: vec![],
            default_hint: "(default: https://kobe.kunobi.ninja)",
            is_password: false,
            visible_when: None,
        },
        FormField {
            label: "Auth mode",
            kind: FieldKind::Select,
            value: auth_str.to_string(),
            options: vec!["none", "token", "oidc"],
            default_hint: "oidc",
            is_password: false,
            visible_when: None,
        },
        FormField {
            label: "Token",
            kind: FieldKind::Password,
            value: config.token.clone().unwrap_or_default(),
            options: vec![],
            default_hint: "(not set)",
            is_password: true,
            visible_when: Some((1, "token")), // only visible when auth mode == "token"
        },
    ]
}

fn fields_to_config(fields: &[FormField]) -> CliConfig {
    let endpoint = if fields[0].value.is_empty() {
        None
    } else {
        Some(fields[0].value.clone())
    };

    let auth = match fields[1].value.as_str() {
        "none" => AuthMode::None,
        "token" => AuthMode::Token,
        _ => AuthMode::Oidc,
    };

    let token = if fields[2].value.is_empty() {
        None
    } else {
        Some(fields[2].value.clone())
    };

    CliConfig {
        endpoint,
        auth,
        token,
    }
}

// ── Main TUI entry point ─────────────────────────────────────────────────

pub fn run_config_tui() -> Result<()> {
    let config = CliConfig::load()?;
    let fields = build_fields(&config);

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut state = EditorState {
        fields,
        cursor: 0,
        mode: Mode::Navigate,
        edit_buffer: String::new(),
        edit_cursor: 0,
        dirty: false,
        status: None,
    };

    loop {
        terminal.draw(|f| draw(f, &state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match state.mode {
                    Mode::Navigate => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if state.dirty {
                                state.mode = Mode::ConfirmQuit;
                            } else {
                                break;
                            }
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            // Skip hidden fields
                            let mut next = state.cursor;
                            loop {
                                if next == 0 {
                                    break;
                                }
                                next -= 1;
                                if state.fields[next].visible(&state.fields) {
                                    break;
                                }
                            }
                            if state.fields[next].visible(&state.fields) {
                                state.cursor = next;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            let mut next = state.cursor;
                            loop {
                                if next >= state.fields.len() - 1 {
                                    break;
                                }
                                next += 1;
                                if state.fields[next].visible(&state.fields) {
                                    break;
                                }
                            }
                            if state.fields[next].visible(&state.fields) {
                                state.cursor = next;
                            }
                        }
                        KeyCode::Enter => {
                            let field = &state.fields[state.cursor];
                            match field.kind {
                                FieldKind::Select => {
                                    // Cycle through options
                                    let current = &state.fields[state.cursor].value;
                                    let opts = &state.fields[state.cursor].options;
                                    let idx = opts.iter().position(|o| o == current).unwrap_or(0);
                                    let next = (idx + 1) % opts.len();
                                    state.fields[state.cursor].value = opts[next].to_string();
                                    state.dirty = true;
                                }
                                _ => {
                                    state.edit_buffer = state.fields[state.cursor].value.clone();
                                    state.edit_cursor = state.edit_buffer.len();
                                    state.mode = Mode::Editing;
                                }
                            }
                        }
                        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let config = fields_to_config(&state.fields);
                            config.save()?;
                            state.dirty = false;
                            state.status = Some("Saved!".to_string());
                        }
                        _ => {}
                    },
                    Mode::Editing => match key.code {
                        KeyCode::Enter | KeyCode::Esc => {
                            if key.code == KeyCode::Enter {
                                state.fields[state.cursor].value = state.edit_buffer.clone();
                                state.dirty = true;
                            }
                            state.mode = Mode::Navigate;
                        }
                        KeyCode::Char(c) => {
                            state.edit_buffer.insert(state.edit_cursor, c);
                            state.edit_cursor += 1;
                        }
                        KeyCode::Backspace => {
                            if state.edit_cursor > 0 {
                                state.edit_cursor -= 1;
                                state.edit_buffer.remove(state.edit_cursor);
                            }
                        }
                        KeyCode::Left => {
                            if state.edit_cursor > 0 {
                                state.edit_cursor -= 1;
                            }
                        }
                        KeyCode::Right => {
                            if state.edit_cursor < state.edit_buffer.len() {
                                state.edit_cursor += 1;
                            }
                        }
                        KeyCode::Home => state.edit_cursor = 0,
                        KeyCode::End => state.edit_cursor = state.edit_buffer.len(),
                        _ => {}
                    },
                    Mode::ConfirmQuit => match key.code {
                        KeyCode::Char('y') => break,
                        KeyCode::Char('s') => {
                            let config = fields_to_config(&state.fields);
                            config.save()?;
                            break;
                        }
                        _ => state.mode = Mode::Navigate,
                    },
                    Mode::ConfirmSave => match key.code {
                        KeyCode::Char('y') => {
                            let config = fields_to_config(&state.fields);
                            config.save()?;
                            state.dirty = false;
                            state.status = Some("Saved!".to_string());
                            state.mode = Mode::Navigate;
                        }
                        _ => state.mode = Mode::Navigate,
                    },
                }
            }
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

// ── Drawing ──────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, state: &EditorState) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(10),   // Form
            Constraint::Length(3), // Status bar
        ])
        .split(area);

    // Title
    let title = Paragraph::new(" Kobe Configuration")
        .style(Style::default().fg(Color::Cyan).bold())
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Form fields
    let form_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Settings ")
        .title_style(Style::default().fg(Color::White).bold());

    let inner = form_block.inner(chunks[1]);
    f.render_widget(form_block, chunks[1]);

    let visible_fields: Vec<(usize, &FormField)> = state
        .fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.visible(&state.fields))
        .collect();

    let field_height = 2u16;
    for (vi, (i, field)) in visible_fields.iter().enumerate() {
        let y = inner.y + (vi as u16) * field_height;
        if y + field_height > inner.y + inner.height {
            break;
        }

        let field_area = Rect::new(inner.x, y, inner.width, field_height);
        let is_selected = *i == state.cursor;
        let is_editing = is_selected && state.mode == Mode::Editing;

        // Label
        let label_style = if is_selected {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::Gray)
        };

        let indicator = if is_selected { "▸ " } else { "  " };
        let label = format!("{indicator}{}", field.label);

        // Value
        let value_text = if is_editing {
            if field.is_password {
                format!("{}_", "*".repeat(state.edit_buffer.len()))
            } else {
                let mut buf = state.edit_buffer.clone();
                buf.insert(state.edit_cursor, '▎');
                buf
            }
        } else if field.kind == FieldKind::Select {
            let opts: Vec<String> = field
                .options
                .iter()
                .map(|o| {
                    if *o == field.value.as_str() {
                        format!("[{}]", o)
                    } else {
                        format!(" {} ", o)
                    }
                })
                .collect();
            opts.join("  ")
        } else {
            field.display_value()
        };

        let value_style = if is_editing {
            Style::default().fg(Color::White)
        } else if field.is_placeholder() {
            Style::default().fg(Color::DarkGray).italic()
        } else if field.is_password {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };

        let line = Line::from(vec![
            Span::styled(format!("{label:<20}"), label_style),
            Span::styled(value_text, value_style),
        ]);

        f.render_widget(Paragraph::new(line), field_area);
    }

    // Status bar
    let status_text = match state.mode {
        Mode::ConfirmQuit => {
            " Unsaved changes. [y] quit  [s] save & quit  [any] cancel".to_string()
        }
        Mode::ConfirmSave => " Save changes? [y] yes  [any] cancel".to_string(),
        Mode::Editing => " Editing — Enter to confirm, Esc to cancel".to_string(),
        Mode::Navigate => {
            let mut parts = vec![
                " ↑↓ navigate",
                " Enter edit/cycle",
                " Ctrl+S save",
                " q quit",
            ];
            if state.dirty {
                parts.push(" [modified]");
            }
            if let Some(ref s) = state.status {
                parts.push(" ");
                parts.push(s);
            }
            parts.join("  │")
        }
    };

    let status_style = match state.mode {
        Mode::ConfirmQuit => Style::default().fg(Color::Red).bold(),
        Mode::Editing => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::DarkGray),
    };

    let status = Paragraph::new(status_text)
        .style(status_style)
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(status, chunks[2]);
}
