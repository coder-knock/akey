//! Output discipline: stdout carries data only, diagnostics always go to stderr; `--json` uses a uniform envelope.
//!
//! This is the **primary interface** AI consumes, so the format is the contract (`REQUIREMENTS.md` FR-3).

use std::io::Write as _;

use serde::Serialize;

use crate::error::{Error, ErrorBody, Result};

/// Placeholder for a concealed secret. Fixed length, never leaks the real length.
pub const REDACTED: &str = "********";

/// Replacement text used when `akey run` masks child-process output.
pub const TAINTED: &str = "<concealed by akey>";

const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    #[default]
    Human,
    Json,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Human => "human",
            Format::Json => "json",
        }
    }
}

#[derive(Serialize)]
struct OkEnvelope<'a, T> {
    ok: bool,
    data: &'a T,
}

#[derive(Serialize)]
struct ErrEnvelope {
    ok: bool,
    error: ErrorBody,
}

#[derive(Debug, Clone)]
pub struct Output {
    format: Format,
    quiet: bool,
    color: bool,
}

impl Output {
    pub fn new(format: Format, quiet: bool, color: bool) -> Self {
        Output {
            format,
            quiet,
            color,
        }
    }

    /// Default sink for unit tests and in-library calls.
    pub fn human() -> Self {
        Output::new(Format::Human, false, false)
    }

    pub fn is_json(&self) -> bool {
        self.format == Format::Json
    }

    pub fn quiet(&self) -> bool {
        self.quiet
    }

    /// Success sink. `human` and `data` must describe the same thing — one source, so the modes cannot drift apart.
    pub fn emit<T: Serialize>(&self, human: impl Into<String>, data: &T) -> Result<()> {
        match self.format {
            Format::Json => {
                let envelope = OkEnvelope { ok: true, data };
                self.write_out(&to_json(&envelope)?)
            }
            Format::Human => {
                if self.quiet {
                    return Ok(());
                }
                self.write_out(&human.into())
            }
        }
    }

    /// Success with no data body (e.g. `rm`).
    pub fn emit_empty(&self) -> Result<()> {
        self.emit("", &serde_json::Value::Null)
    }

    /// In human mode writes one raw line straight through; suppressed in JSON mode (data is `emit`'s job).
    pub fn note(&self, text: &str) {
        if self.format == Format::Human && !self.quiet {
            let _ = writeln!(std::io::stdout(), "{text}");
        }
    }

    pub fn warn(&self, msg: &str) {
        if !self.quiet {
            eprintln!(
                "{}",
                self.paint(
                    &format!("{}{msg}", crate::i18n::m("warning: ", "警告：")),
                    YELLOW
                )
            );
        }
    }

    pub fn error(&self, err: &Error) {
        if self.format == Format::Json {
            let envelope = ErrEnvelope {
                ok: false,
                error: ErrorBody::from(err),
            };
            let rendered = to_json(&envelope).unwrap_or_else(|_| err.to_string());
            eprintln!("{rendered}");
            return;
        }
        // The trailing space lives inside the English label: a full-width colon already
        // supplies the gap in Chinese, and a shared "{} {err}" format cannot vary it.
        eprintln!(
            "{}{err}",
            self.paint(crate::i18n::m("error: ", "错误："), RED)
        );
        if let Some(hint) = err.hint() {
            eprintln!("  {}{hint}", crate::i18n::m("hint: ", "提示："));
        }
    }

    fn write_out(&self, line: &str) -> Result<()> {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(line.as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        Ok(())
    }

    fn paint(&self, text: &str, color: &str) -> String {
        if self.color {
            format!("{color}{text}{RESET}")
        } else {
            text.to_string()
        }
    }
}

impl Default for Output {
    fn default() -> Self {
        Output::human()
    }
}

/// Structures we construct ourselves cannot fail to serialize; a real failure can only be an internal error.
fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| Error::Io(std::io::Error::other(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_envelope_wraps_data_under_ok() {
        let rendered = to_json(&OkEnvelope {
            ok: true,
            data: &serde_json::json!({"name": "openai"}),
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["data"]["name"], "openai");
    }

    #[test]
    fn error_envelope_carries_code_message_and_hint() {
        let err = Error::not_found("no entry named 'foo'");
        let rendered = to_json(&ErrEnvelope {
            ok: false,
            error: ErrorBody::from(&err),
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"]["code"], "not_found");
        assert!(parsed["error"]["hint"].is_string());
    }

    #[test]
    fn redaction_placeholder_is_fixed_width() {
        assert_eq!(REDACTED.len(), 8);
        assert!(REDACTED.chars().all(|c| c == '*'));
    }
}
