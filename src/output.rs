//! 输出纪律：stdout 只放数据，诊断一律 stderr；`--json` 走统一信封。
//!
//! 这是 AI 消费的**主要接口**，格式即契约（`REQUIREMENTS.md` FR-3）。

use std::io::Write as _;

use serde::Serialize;

use crate::error::{Error, ErrorBody, Result};

/// 隐藏的秘密占位符。长度固定，不泄漏真实长度。
pub const REDACTED: &str = "********";

/// `akey run` 遮蔽子进程输出时使用的替换文本。
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

    /// 单测与库内调用用的默认出口。
    pub fn human() -> Self {
        Output::new(Format::Human, false, false)
    }

    pub fn is_json(&self) -> bool {
        self.format == Format::Json
    }

    pub fn quiet(&self) -> bool {
        self.quiet
    }

    /// 成功出口。`human` 与 `data` 必须描述同一件事——两者同源，避免模式间漂移。
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

    /// 无数据体的成功（如 `rm`）。
    pub fn emit_empty(&self) -> Result<()> {
        self.emit("", &serde_json::Value::Null)
    }

    /// 人类模式下直接写一行原文；JSON 模式抑制（数据应由 `emit` 负责）。
    pub fn note(&self, text: &str) {
        if self.format == Format::Human && !self.quiet {
            let _ = writeln!(std::io::stdout(), "{text}");
        }
    }

    pub fn warn(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{}", self.paint(&format!("warning: {msg}"), YELLOW));
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
        eprintln!("{} {err}", self.paint("error:", RED));
        if let Some(hint) = err.hint() {
            eprintln!("  hint: {hint}");
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

/// 我们自己构造的结构不可能序列化失败；真失败也只可能是内部错误。
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
