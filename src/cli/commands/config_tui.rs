use anyhow::Result;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::*;
use std::io::stdout;
use std::time::Duration;

use super::config::{AuthMode, CliConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
enum EditTarget {
    Legacy,
    Target(String),
}

impl EditTarget {
    fn label(&self) -> String {
        match self {
            Self::Legacy => "legacy config".to_string(),
            Self::Target(name) => format!("target {name}"),
        }
    }
}

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
    /// (field_index, required_value) — only active when fields[index].value == required_value
    active_when: Option<(usize, &'static str)>,
    inactive_hint: Option<&'static str>,
}

impl FormField {
    fn display_value(&self, active: bool) -> String {
        if self.value.is_empty() {
            if active {
                self.default_hint.to_string()
            } else {
                self.inactive_hint.unwrap_or(self.default_hint).to_string()
            }
        } else if self.is_password {
            let masked = "*".repeat(self.value.len().min(20));
            if active {
                masked
            } else {
                format!("{masked}  (inactive)")
            }
        } else if active {
            self.value.clone()
        } else {
            format!("{}  (inactive)", self.value)
        }
    }

    fn is_placeholder(&self) -> bool {
        self.value.is_empty()
    }

    fn is_active(&self, fields: &[FormField]) -> bool {
        match self.active_when {
            Some((idx, val)) => fields.get(idx).map(|f| f.value == val).unwrap_or(true),
            None => true,
        }
    }
}

// ── Editor state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Navigate,
    Editing,
    ConfirmQuit,
}

struct EditorState {
    target: EditTarget,
    current_target: Option<String>,
    fields: Vec<FormField>,
    cursor: usize,
    mode: Mode,
    edit_buffer: String,
    edit_cursor: usize,
    dirty: bool,
    status: Option<String>,
}

fn resolve_edit_target(config: &CliConfig, target_override: Option<&str>) -> Result<EditTarget> {
    if let Some(name) = target_override {
        if config.targets.contains_key(name) {
            return Ok(EditTarget::Target(name.to_string()));
        }
        anyhow::bail!("Unknown target '{name}'. Run: kobe config list");
    }

    if let Some(name) = &config.current_target {
        if config.targets.contains_key(name) {
            return Ok(EditTarget::Target(name.clone()));
        }
        anyhow::bail!("Current target '{name}' does not exist. Run: kobe config list");
    }

    Ok(EditTarget::Legacy)
}

fn build_fields(config: &CliConfig, target: &EditTarget) -> Result<Vec<FormField>> {
    let (endpoint, auth, token, ssh_fingerprint) = match target {
        EditTarget::Legacy => (
            config.endpoint.clone().unwrap_or_default(),
            config.auth.clone(),
            config.token.clone().unwrap_or_default(),
            config.ssh_fingerprint.clone().unwrap_or_default(),
        ),
        EditTarget::Target(name) => {
            let target = config
                .targets
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("Unknown target '{name}'. Run: kobe config list"))?;
            (
                target.endpoint.clone(),
                target.auth.clone(),
                target.token.clone().unwrap_or_default(),
                target.ssh_fingerprint.clone().unwrap_or_default(),
            )
        }
    };

    let auth_str = match auth {
        AuthMode::None => "none",
        AuthMode::Token => "token",
        AuthMode::Oidc => "oidc",
        AuthMode::Ssh => "ssh",
    };

    Ok(vec![
        FormField {
            label: "Endpoint",
            kind: FieldKind::Text,
            value: endpoint,
            options: vec![],
            default_hint: "(default: https://kobe.kunobi.ninja)",
            is_password: false,
            active_when: None,
            inactive_hint: None,
        },
        FormField {
            label: "Auth mode",
            kind: FieldKind::Select,
            value: auth_str.to_string(),
            options: vec!["none", "token", "oidc", "ssh"],
            default_hint: "oidc",
            is_password: false,
            active_when: None,
            inactive_hint: None,
        },
        FormField {
            label: "Token",
            kind: FieldKind::Password,
            value: token,
            options: vec![],
            default_hint: "(not set)",
            is_password: true,
            active_when: Some((1, "token")),
            inactive_hint: Some("(used when auth=token)"),
        },
        FormField {
            label: "SSH fingerprint",
            kind: FieldKind::Text,
            value: ssh_fingerprint,
            options: vec![],
            default_hint: "(optional - uses ~/.ssh/id_ed25519)",
            is_password: false,
            active_when: Some((1, "ssh")),
            inactive_hint: Some("(used when auth=ssh)"),
        },
    ])
}

fn fields_to_config(
    fields: &[FormField],
    previous: &CliConfig,
    target: &EditTarget,
) -> Result<CliConfig> {
    let endpoint = if fields[0].value.is_empty() {
        None
    } else {
        Some(fields[0].value.clone())
    };

    let auth = match fields[1].value.as_str() {
        "none" => AuthMode::None,
        "token" => AuthMode::Token,
        "ssh" => AuthMode::Ssh,
        _ => AuthMode::Oidc,
    };

    let token = if fields[2].value.is_empty() {
        None
    } else {
        Some(fields[2].value.clone())
    };

    let ssh_fingerprint = if fields[3].value.is_empty() {
        None
    } else {
        Some(fields[3].value.clone())
    };

    let mut config = CliConfig {
        current_target: previous.current_target.clone(),
        targets: previous.targets.clone(),
        endpoint: previous.endpoint.clone(),
        auth: previous.auth.clone(),
        token: previous.token.clone(),
        ssh_fingerprint: previous.ssh_fingerprint.clone(),
    };

    match target {
        EditTarget::Legacy => Ok(CliConfig {
            current_target: config.current_target,
            targets: config.targets,
            endpoint,
            auth,
            token,
            ssh_fingerprint,
        }),
        EditTarget::Target(name) => {
            let target = config
                .targets
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("Unknown target '{name}'. Run: kobe config list"))?;
            if let Some(endpoint) = endpoint {
                target.endpoint = endpoint;
            }
            target.auth = auth;
            target.token = token;
            target.ssh_fingerprint = ssh_fingerprint;
            Ok(config)
        }
    }
}

fn cycle_select(field: &mut FormField, backwards: bool) -> bool {
    if field.kind != FieldKind::Select || field.options.is_empty() {
        return false;
    }

    let idx = field
        .options
        .iter()
        .position(|option| *option == field.value)
        .unwrap_or(0);
    let next = if backwards {
        if idx == 0 {
            field.options.len() - 1
        } else {
            idx - 1
        }
    } else {
        (idx + 1) % field.options.len()
    };
    field.value = field.options[next].to_string();
    true
}

// ── Main TUI entry point ─────────────────────────────────────────────────

pub fn run_config_tui(target_override: Option<&str>) -> Result<()> {
    let config = CliConfig::load()?;
    let target = resolve_edit_target(&config, target_override)?;
    let fields = build_fields(&config, &target)?;

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut state = EditorState {
        target,
        current_target: config.current_target.clone(),
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
                            state.status = None;
                            if state.cursor > 0 {
                                state.cursor -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.status = None;
                            if state.cursor + 1 < state.fields.len() {
                                state.cursor += 1;
                            }
                        }
                        KeyCode::Left => {
                            state.status = None;
                            if cycle_select(&mut state.fields[state.cursor], true) {
                                state.dirty = true;
                            }
                        }
                        KeyCode::Right => {
                            state.status = None;
                            if cycle_select(&mut state.fields[state.cursor], false) {
                                state.dirty = true;
                            }
                        }
                        KeyCode::Enter => {
                            state.status = None;
                            let field = &state.fields[state.cursor];
                            if field.kind != FieldKind::Select {
                                state.edit_buffer = field.value.clone();
                                state.edit_cursor = state.edit_buffer.len();
                                state.mode = Mode::Editing;
                            }
                        }
                        KeyCode::Char('s') => {
                            let updated_config =
                                fields_to_config(&state.fields, &config, &state.target)?;
                            updated_config.save()?;
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
                        KeyCode::Backspace if state.edit_cursor > 0 => {
                            state.edit_cursor -= 1;
                            state.edit_buffer.remove(state.edit_cursor);
                        }
                        KeyCode::Left if state.edit_cursor > 0 => {
                            state.edit_cursor -= 1;
                        }
                        KeyCode::Right if state.edit_cursor < state.edit_buffer.len() => {
                            state.edit_cursor += 1;
                        }
                        KeyCode::Home => state.edit_cursor = 0,
                        KeyCode::End => state.edit_cursor = state.edit_buffer.len(),
                        _ => {}
                    },
                    Mode::ConfirmQuit => match key.code {
                        KeyCode::Char('y') => break,
                        KeyCode::Char('s') => {
                            let updated_config =
                                fields_to_config(&state.fields, &config, &state.target)?;
                            updated_config.save()?;
                            break;
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
            Constraint::Length(4), // Header
            Constraint::Min(10),   // Form
            Constraint::Length(3), // Status bar
        ])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            " Kobe Configuration",
            Style::default().fg(Color::Cyan).bold(),
        )),
        Line::from(vec![
            Span::styled(" editing: ", Style::default().fg(Color::Gray)),
            Span::styled(state.target.label(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" current target: ", Style::default().fg(Color::Gray)),
            Span::styled(
                state.current_target.as_deref().unwrap_or("(none)"),
                Style::default().fg(Color::White),
            ),
        ]),
    ])
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(header, chunks[0]);

    let form_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Settings ")
        .title_style(Style::default().fg(Color::White).bold());

    let inner = form_block.inner(chunks[1]);
    f.render_widget(form_block, chunks[1]);

    let field_height = 2u16;
    for (i, field) in state.fields.iter().enumerate() {
        let y = inner.y + (i as u16) * field_height;
        if y + field_height > inner.y + inner.height {
            break;
        }

        let active = field.is_active(&state.fields);
        let field_area = Rect::new(inner.x, y, inner.width, field_height);
        let is_selected = i == state.cursor;
        let is_editing = is_selected && state.mode == Mode::Editing;

        let label_style = if is_selected {
            Style::default().fg(Color::Yellow).bold()
        } else if active {
            Style::default().fg(Color::Gray)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let indicator = if is_selected { "▸ " } else { "  " };
        let label = format!("{indicator}{}", field.label);

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
                .map(|option| {
                    if *option == field.value.as_str() {
                        format!("[{}]", option)
                    } else {
                        format!(" {} ", option)
                    }
                })
                .collect();
            opts.join("  ")
        } else {
            field.display_value(active)
        };

        let value_style = if is_editing {
            Style::default().fg(Color::White)
        } else if !active || field.is_placeholder() {
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

    let status_text = match state.mode {
        Mode::ConfirmQuit => {
            " Unsaved changes. [y] quit  [s] save & quit  [any] cancel".to_string()
        }
        Mode::Editing => " Editing - Enter to confirm, Esc to cancel".to_string(),
        Mode::Navigate => {
            let mut parts = vec![
                " ↑↓ navigate",
                " Enter edit",
                " ←→ change select",
                " s save",
                " q quit",
            ];
            if !state.fields[state.cursor].is_active(&state.fields) {
                parts.push(" field inactive for current auth mode");
            }
            if state.dirty {
                parts.push(" [modified]");
            }
            if let Some(ref status) = state.status {
                parts.push(" ");
                parts.push(status);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::config::KobeTarget;
    use std::collections::BTreeMap;

    fn sample_target(endpoint: &str, auth: AuthMode) -> KobeTarget {
        KobeTarget {
            endpoint: endpoint.to_string(),
            auth,
            token: None,
            ssh_fingerprint: None,
        }
    }

    #[test]
    fn resolve_edit_target_prefers_requested_target() {
        let mut targets = BTreeMap::new();
        targets.insert(
            "prod".to_string(),
            sample_target("https://prod.example.com", AuthMode::Oidc),
        );
        targets.insert(
            "staging".to_string(),
            sample_target("https://staging.example.com", AuthMode::Ssh),
        );

        let config = CliConfig {
            current_target: Some("prod".to_string()),
            targets,
            ..CliConfig::default()
        };

        let target = resolve_edit_target(&config, Some("staging")).unwrap();
        assert_eq!(target, EditTarget::Target("staging".to_string()));
    }

    #[test]
    fn build_fields_keeps_auth_specific_fields_visible() {
        let mut targets = BTreeMap::new();
        targets.insert(
            "prod".to_string(),
            sample_target("https://prod.example.com", AuthMode::Oidc),
        );

        let config = CliConfig {
            current_target: Some("prod".to_string()),
            targets,
            ..CliConfig::default()
        };

        let fields = build_fields(&config, &EditTarget::Target("prod".to_string())).unwrap();
        assert_eq!(fields.len(), 4);
        assert!(!fields[2].is_active(&fields));
        assert!(!fields[3].is_active(&fields));
    }

    #[test]
    fn build_fields_for_target_does_not_inherit_legacy_credentials() {
        let mut targets = BTreeMap::new();
        targets.insert(
            "prod".to_string(),
            sample_target("https://prod.example.com", AuthMode::Oidc),
        );

        let config = CliConfig {
            current_target: Some("prod".to_string()),
            targets,
            endpoint: Some("https://legacy.example.com".to_string()),
            auth: AuthMode::Token,
            token: Some("legacy-token".to_string()),
            ssh_fingerprint: Some("SHA256:legacy".to_string()),
        };

        let fields = build_fields(&config, &EditTarget::Target("prod".to_string())).unwrap();
        assert_eq!(fields[0].value, "https://prod.example.com");
        assert_eq!(fields[1].value, "oidc");
        assert!(fields[2].value.is_empty());
        assert!(fields[3].value.is_empty());
    }

    #[test]
    fn fields_to_config_updates_selected_target_only() {
        let mut targets = BTreeMap::new();
        targets.insert(
            "prod".to_string(),
            sample_target("https://prod.example.com", AuthMode::Oidc),
        );

        let previous = CliConfig {
            current_target: Some("prod".to_string()),
            targets,
            endpoint: Some("https://legacy.example.com".to_string()),
            auth: AuthMode::Token,
            token: Some("legacy-token".to_string()),
            ssh_fingerprint: None,
        };

        let fields = vec![
            FormField {
                label: "Endpoint",
                kind: FieldKind::Text,
                value: "https://new.example.com".to_string(),
                options: vec![],
                default_hint: "",
                is_password: false,
                active_when: None,
                inactive_hint: None,
            },
            FormField {
                label: "Auth mode",
                kind: FieldKind::Select,
                value: "ssh".to_string(),
                options: vec![],
                default_hint: "",
                is_password: false,
                active_when: None,
                inactive_hint: None,
            },
            FormField {
                label: "Token",
                kind: FieldKind::Password,
                value: "".to_string(),
                options: vec![],
                default_hint: "",
                is_password: true,
                active_when: Some((1, "token")),
                inactive_hint: None,
            },
            FormField {
                label: "SSH fingerprint",
                kind: FieldKind::Text,
                value: "SHA256:test".to_string(),
                options: vec![],
                default_hint: "",
                is_password: false,
                active_when: Some((1, "ssh")),
                inactive_hint: None,
            },
        ];

        let updated =
            fields_to_config(&fields, &previous, &EditTarget::Target("prod".to_string())).unwrap();

        assert_eq!(
            updated.endpoint.as_deref(),
            Some("https://legacy.example.com")
        );
        assert_eq!(updated.auth, AuthMode::Token);

        let prod = updated.targets.get("prod").unwrap();
        assert_eq!(prod.endpoint, "https://new.example.com");
        assert_eq!(prod.auth, AuthMode::Ssh);
        assert_eq!(prod.ssh_fingerprint.as_deref(), Some("SHA256:test"));
    }
}
