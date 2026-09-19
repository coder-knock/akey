//! 注入机制：解析引用 → 构造环境 → 拉起子进程 → 遮蔽回显。
//!
//! 与 `cmd::deliver` 的分工：这里只做机制，不做参数解析与策略判断。

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::inject::mask::Masker;
use crate::reference::{self, Reference};
use crate::vault::model::{Category, Entry, Vault};
use crate::vault::store::Store;

/// 一次注入的完整环境。
#[derive(Debug, Default)]
pub struct Injection {
    /// 变量名 → 明文。顺序稳定，便于测试与 `--dry-run` 预览。
    pub vars: Vec<(String, Zeroizing<String>)>,
}

impl Injection {
    /// 供遮蔽管线使用的明文清单。
    pub fn secrets(&self) -> Vec<String> {
        self.vars.iter().map(|(_, v)| v.to_string()).collect()
    }
}

/// 把 `--with` / `--bundle` / `--env-file` 合成一份环境。
///
/// 优先级（高 → 低）：`--with` > `--bundle` > `--env-file`（多个文件时后者覆盖前者）
/// > 进程自身环境。
///
/// 三种 `--with` 形态：
/// - `VAR=akey://…`：引用（也允许引用嵌在别的字符串里，如 `AUTH=Bearer akey://a/b`）
/// - `VAR=ITEM`：条目名，取该条目 `category` 的默认秘密字段
/// - `ITEM`：变量名由条目名派生（大写、非字母数字 → `_`），值同上
///
/// `--bundle` 只接受 `env-bundle` 条目，注入它的**全部字段**（变量名 = 字段 slug 大写）；
/// `--env-file` 按 dotenv 语法解析，值里的 `akey://` 引用会被解成明文。
/// 结果按变量名升序，保证同一组输入得到同一份环境。
///
/// `store` 目前不参与求值：解引用只需要 `vault`。保留它是因为调用方（`cmd` 层）手上
/// 就有它，而注入策略将来若要按设备/仓库判断（如审计设备名）就不必再改签名。
pub fn resolve(
    _store: &Store,
    vault: &Vault,
    specs: &[String],
    bundles: &[String],
    env_files: &[PathBuf],
) -> Result<Injection> {
    // 低 → 高依次插入：`BTreeMap` 的"后写胜出"就是优先级，末尾的键序就是确定性输出。
    let mut vars: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();

    for path in env_files {
        for (name, value) in load_env_file(path)? {
            vars.insert(name, render_refs(vault, &value)?);
        }
    }

    for bundle in bundles {
        let entry = require_env_bundle(vault, bundle)?;
        if entry.fields.is_empty() {
            return Err(Error::usage(format!(
                "env-bundle '{}' has no fields to inject",
                entry.name
            )));
        }
        for field in &entry.fields {
            vars.insert(env_name(&field.id), Zeroizing::new(field.value().to_string()));
        }
    }

    for spec in specs {
        let (name, value) = match spec.split_once('=') {
            Some((name, raw)) => {
                let name = name.trim();
                if !is_env_var_name(name) {
                    return Err(Error::usage(format!(
                        "--with '{spec}': '{name}' is not a valid environment variable name"
                    )));
                }
                (name.to_string(), with_value(vault, raw)?)
            }
            None => {
                let entry = vault.find(spec)?;
                (env_name(&entry.name), default_secret(entry)?)
            }
        };
        vars.insert(name, value);
    }

    Ok(Injection {
        vars: vars.into_iter().collect(),
    })
}

/// 一次注入的"授权面"：`cmd` 层用它把令牌作用域卡在注入之前。
///
/// 注入等于把明文交给子进程。`run` 不走 `gate_reveal`（明文不交给调用者），
/// 但作用域必须照样生效——否则被限制在单条目的令牌只要把值注入
/// `sh -c 'cat'` 就能读到任何条目。
#[derive(Debug, Default)]
pub struct Touch {
    /// 可能含 `akey://` 引用的原文（`--with` 各 spec + 每个 `--env-file` 的内容）：
    /// 交给 `Ctx::authorize_references`。
    pub texts: Vec<String>,
    /// 不带引用就直接指条目（`VAR=ITEM` / `ITEM` / `--bundle`）的那些写法解析出的
    /// **条目名**：交给 `Ctx::authorize`。存名字而不是用户原样输入，因为作用域比的是名字
    /// （用户可能传的是 22 位 ID）。
    pub items: Vec<String>,
    /// 本次注入会触碰的全部条目名（升序去重），用作审计 `subject`。
    pub subjects: Vec<String>,
}

/// 算出一次注入的授权面。为了不把 [`resolve`] 的签名撑大，这里会重读一遍 env 文件
/// （dotenv 文件只有几百字节，而授权必须在解密出明文之前完成）。
pub fn touch(
    vault: &Vault,
    specs: &[String],
    bundles: &[String],
    env_files: &[PathBuf],
) -> Result<Touch> {
    let mut touch = Touch::default();
    let mut items: BTreeSet<String> = BTreeSet::new();
    let mut subjects: BTreeSet<String> = BTreeSet::new();

    for path in env_files {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("cannot read env file {}: {e}", path.display()),
            ))
        })?;
        for raw in reference::extract_references(&content) {
            subjects.insert(vault.find(&parse_ref(&raw)?.item)?.name.clone());
        }
        touch.texts.push(content);
    }

    for bundle in bundles {
        let entry = require_env_bundle(vault, bundle)?;
        items.insert(entry.name.clone());
        subjects.insert(entry.name.clone());
    }

    for spec in specs {
        match spec.split_once('=') {
            Some((_, raw)) if raw.contains(reference::SCHEME) => {
                for raw in reference::extract_references(raw.trim()) {
                    subjects.insert(vault.find(&parse_ref(&raw)?.item)?.name.clone());
                }
            }
            Some((_, raw)) => {
                let name = vault.find(raw.trim())?.name.clone();
                items.insert(name.clone());
                subjects.insert(name);
            }
            None => {
                let name = vault.find(spec)?.name.clone();
                items.insert(name.clone());
                subjects.insert(name);
            }
        }
        touch.texts.push(spec.clone());
    }

    touch.items = items.into_iter().collect();
    touch.subjects = subjects.into_iter().collect();
    Ok(touch)
}

/// 拉起子进程并透传退出码。
///
/// `mask = true` 时 stdout/stderr 走管道并遮蔽；`false` 时三个 fd 全部 inherit
/// （保留 TTY，交互式子进程需要）。
pub fn execute(command: &[String], injection: &Injection, mask: bool) -> Result<i32> {
    if !mask {
        // 不遮蔽就直接继承：保留 TTY 语义，也省掉一次管道拷贝（含注入为空的情形）。
        return spawn_child(command, injection, ChildIo::Inherit);
    }
    spawn_child(
        command,
        injection,
        ChildIo::Piped {
            mask: true,
            out: Box::new(std::io::stdout()),
            err: Box::new(std::io::stderr()),
        },
    )
}

/// 把输入文本里的全部 `akey://` 引用替换为明文。
///
/// 未命中的引用 → `NotFound` 且点名该引用（不回显字段值：错误信息里没有秘密）。
pub fn render_template(vault: &Vault, input: &str) -> Result<String> {
    Ok(render_refs(vault, input)?.to_string())
}

/// 环境变量名派生：大写，非字母数字 → `_`。
///
/// 条目名与字段 slug 都可能含 `.` / `-`，直接大写会得到 shell 无法引用的名字，
/// 所以统一折叠成下划线。`export` / `import` 用它保证两边命名一致。
pub fn env_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// 解析 dotenv 文本。
///
/// 支持：`export ` 前缀、整行 `#` 注释、单/双引号、空行、值里含 `=`、`\r\n` 行尾。
/// 双引号值里的 `\n` `\r` `\t` `\\` `\"` 会转义，单引号值一律字面。
/// 语法错误 → `usage` 并点名 `label`（调用方传文件名）与行号。
pub fn parse_dotenv(label: &str, input: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (index, raw_line) in input.lines().enumerate() {
        let lineno = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
            _ => line,
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::usage(format!(
                "{label}:{lineno}: expected `NAME=value`"
            )));
        };
        let key = key.trim();
        if !is_env_var_name(key) {
            return Err(Error::usage(format!(
                "{label}:{lineno}: '{key}' is not a valid environment variable name"
            )));
        }
        out.push((key.to_string(), unquote(value.trim())));
    }
    Ok(out)
}

/// `--with` 的右半：含 `akey://` 就替换引用，否则按条目名取默认秘密字段。
fn with_value(vault: &Vault, raw: &str) -> Result<Zeroizing<String>> {
    let raw = raw.trim();
    if raw.contains(reference::SCHEME) {
        return render_refs(vault, raw);
    }
    default_secret(vault.find(raw)?)
}

/// 条目 `category` 对应的默认秘密字段值。
fn default_secret(entry: &Entry) -> Result<Zeroizing<String>> {
    let label = entry.category.default_secret_field();
    if label.is_empty() {
        return Err(Error::usage(format!(
            "entry '{}' is an env-bundle and has no single secret field; use `--bundle {}`",
            entry.name, entry.name
        )));
    }
    let field = entry.field(label).ok_or_else(|| {
        Error::not_found(format!(
            "entry '{}' has no '{}' field to inject",
            entry.name, label
        ))
    })?;
    Ok(Zeroizing::new(field.value().to_string()))
}

/// `--bundle` 只接受 `env-bundle` 条目——其他分类把单个字段摊平成环境变量只会让人意外。
fn require_env_bundle<'a>(vault: &'a Vault, item: &str) -> Result<&'a Entry> {
    let entry = vault.find(item)?;
    if entry.category != Category::EnvBundle {
        return Err(Error::usage(format!(
            "entry '{}' is a {}, not an env-bundle; use `--with` for single values",
            entry.name, entry.category
        )));
    }
    Ok(entry)
}

/// 把文本里的每个引用替换成明文。引用原文按出现顺序处理，重复引用各自替换。
fn render_refs(vault: &Vault, input: &str) -> Result<Zeroizing<String>> {
    let now = Utc::now();
    let rendered = walk_refs(input, |raw| resolve_ref(vault, raw, now))?;
    Ok(Zeroizing::new(rendered))
}

/// 按出现顺序遍历 `input` 里的 `akey://` 引用，用 `visit` 的返回值替换。
///
/// 引用边界由 [`reference::extract_references`] 决定（唯一真相源）；它按出现顺序、
/// 互不重叠地返回原文，因此从游标处 `find` 必命中。
fn walk_refs(input: &str, mut visit: impl FnMut(&str) -> Result<String>) -> Result<String> {
    let raws = reference::extract_references(input);
    if raws.is_empty() {
        return Ok(input.to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for raw in &raws {
        let Some(offset) = input[cursor..].find(raw.as_str()) else {
            // 理论上不可达；真出现偏差就保留原文，绝不错位替换。
            continue;
        };
        let start = cursor + offset;
        out.push_str(&input[cursor..start]);
        out.push_str(&visit(raw)?);
        cursor = start + raw.len();
    }
    out.push_str(&input[cursor..]);
    Ok(out)
}

/// 解析一条引用原文（含 `$VAR` 展开）并求值。
fn resolve_ref(vault: &Vault, raw: &str, now: DateTime<Utc>) -> Result<String> {
    let reference = parse_ref(raw)?;
    match reference::resolve(vault, &reference, now) {
        Ok(value) => Ok(value.to_string()),
        // 点名引用原文，agent 才知道该改哪里；消息里只有名字，没有值。
        Err(Error::NotFound(msg)) => Err(Error::not_found(format!(
            "cannot resolve '{raw}': {msg}"
        ))),
        Err(Error::Ambiguous(msg)) => Err(Error::Ambiguous(format!(
            "cannot resolve '{raw}': {msg}"
        ))),
        Err(other) => Err(other),
    }
}

/// 引用解析的统一入口（`$VAR` 取自当前进程环境）。
fn parse_ref(raw: &str) -> Result<Reference> {
    Reference::parse_in(raw, &|name| std::env::var(name).ok())
}

/// 读并解析一个 `--env-file`。
fn load_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read env file {}: {e}", path.display()),
        ))
    })?;
    parse_dotenv(&path.display().to_string(), &raw)
}

/// 合法的环境变量名：`[A-Za-z_][A-Za-z0-9_]*`。
fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// dotenv 值去引号。单引号一律字面；双引号按 dotenv 约定处理转义。
fn unquote(value: &str) -> String {
    if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        return unescape_double(inner);
    }
    if let Some(inner) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        return inner.to_string();
    }
    value.to_string()
}

/// 双引号值里的转义：`\n` `\r` `\t` `\\` `\"`；未知转义原样保留。
fn unescape_double(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// 子进程的 IO 策略。
enum ChildIo {
    /// 三个 fd 全部继承。保留 TTY 语义（交互式子进程需要），代价是无法遮蔽——
    /// 这正是它只用于 `--no-masking` 的原因。
    Inherit,
    /// stdout/stderr 走管道。`mask` 为真时边读边把秘密换成占位符；为假时原样透传
    /// （`execute` 不会用这个组合，它给测试留出一条可观测的"不遮蔽"通路）。
    Piped {
        mask: bool,
        out: Box<dyn Write + Send>,
        err: Box<dyn Write + Send>,
    },
}

/// 起子进程：环境 = 当前进程环境 + 注入变量（覆盖同名者），退出码原样返回。
fn spawn_child(command: &[String], injection: &Injection, io: ChildIo) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| Error::usage("no command to run; expected `akey run … -- <command>`"))?;
    let mut child = Command::new(program);
    child.args(args);
    for (name, value) in &injection.vars {
        child.env(name, value.as_str());
    }

    match io {
        ChildIo::Inherit => Ok(exit_code(child.status()?)),
        ChildIo::Piped { mask, out, err } => {
            child
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut running = child.spawn()?;
            let stdout = running.stdout.take().ok_or_else(missing_pipe)?;
            let stderr = running.stderr.take().ok_or_else(missing_pipe)?;

            // 两个流必须并行读：单线程读一个流时，另一个流的管道写满就会把子进程和
            // 读端一起卡死。stdin 继续继承，交互式输入不受影响。
            let out_thread = std::thread::spawn({
                let secrets = injection.secrets();
                move || relay(stdout, out, secrets, mask)
            });
            let err_thread = std::thread::spawn({
                let secrets = injection.secrets();
                move || relay(stderr, err, secrets, mask)
            });

            let status = running.wait()?;
            join_relay(out_thread)?;
            join_relay(err_thread)?;
            Ok(exit_code(status))
        }
    }
}

/// `Stdio::piped()` 之后 `take()` 必然成功；拿不到只可能是内部错误。
fn missing_pipe() -> Error {
    Error::Io(std::io::Error::other("child output pipe was not created"))
}

/// 回收读线程。线程 panic 或写失败都要上报；唯独下游先关闭（`| head`）不算错误——
/// 那时子进程的退出码才是调用者要的结果。
fn join_relay(handle: std::thread::JoinHandle<std::io::Result<()>>) -> Result<()> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Ok(Err(e)) => Err(Error::Io(e)),
        Err(_) => Err(Error::Io(std::io::Error::other(
            "output relay thread panicked",
        ))),
    }
}

/// 把一个子进程输出流泵到 `sink`。`mask` 为真时用 [`Masker`] 逐块遮蔽，
/// 否则 [`Masker`] 处于未启用状态、原样穿透。
fn relay(
    mut reader: impl Read,
    mut sink: Box<dyn Write + Send>,
    secrets: Vec<String>,
    mask: bool,
) -> std::io::Result<()> {
    let mut masker = if mask {
        Masker::with_secrets(secrets)
    } else {
        Masker::new()
    };
    let mut buf = [0u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let chunk = masker.push(&buf[..read]);
        if !chunk.is_empty() {
            sink.write_all(&chunk)?;
            sink.flush()?;
        }
    }
    let tail = masker.finish();
    if !tail.is_empty() {
        sink.write_all(&tail)?;
    }
    sink.flush()
}

/// 退出码透传；被信号杀死 → `128 + signal`（shell 惯例）。
fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    status.signal().map_or(1, |signal| 128 + signal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::crypto::DeviceIdentity;
    use crate::output::TAINTED;
    use crate::paths::Paths;
    use crate::vault::model::FieldType;
    use std::sync::{Arc, Mutex};
    use ulid::Ulid;

    fn ulid(tag: u8) -> Ulid {
        Ulid::from_bytes([tag; 16])
    }

    fn field(label: &str, ty: FieldType, value: &str) -> crate::vault::model::Field {
        crate::vault::model::Field::new(label, ty, value.to_string())
    }

    fn fixture() -> Vault {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("时间戳在合法范围内");
        let mut vault = Vault::default();

        let mut openai = Entry::new(ulid(1), "openai".to_string(), Category::Apikey, now);
        openai
            .fields
            .push(field("credential", FieldType::Concealed, "sk-live-OPENAI-SECRET"));
        openai.fields.push(field("org", FieldType::String, "org-acme"));
        vault.entries.insert(openai.id, openai);

        let mut db = Entry::new(ulid(2), "db".to_string(), Category::Database, now);
        db.fields
            .push(field("password", FieldType::Concealed, "db-password-SECRET"));
        db.fields.push(field("host", FieldType::String, "db.internal"));
        vault.entries.insert(db.id, db);

        let mut deploy = Entry::new(ulid(3), "deploy".to_string(), Category::EnvBundle, now);
        deploy
            .fields
            .push(field("API_KEY", FieldType::Concealed, "bundle-API-KEY-value"));
        deploy
            .fields
            .push(field("DB_HOST", FieldType::String, "db.internal"));
        deploy
            .fields
            .push(field("cache-url", FieldType::String, "redis://cache"));
        vault.entries.insert(deploy.id, deploy);

        let mut dotted = Entry::new(ulid(4), "my.api".to_string(), Category::Apikey, now);
        dotted
            .fields
            .push(field("credential", FieldType::Concealed, "sk-dotted-SECRET"));
        vault.entries.insert(dotted.id, dotted);

        vault
    }

    /// 测试用的 `Store`：只构造结构，不碰 `$HOME`、不读写任何文件。
    fn test_store(dir: &Path) -> Store {
        Store {
            paths: Paths::new(dir.join("home")),
            config: Config {
                repo: dir.join("repo"),
                remote: None,
                device_name: "test-device".to_string(),
                reveal_allowed: true,
                created_at: Utc::now(),
            },
            identity: DeviceIdentity::generate("test-device"),
        }
    }

    fn env_file(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("写测试用 env 文件");
        path
    }

    fn var_map(injection: &Injection) -> BTreeMap<String, String> {
        injection
            .vars
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }

    fn specs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn sh(script: &str) -> Vec<String> {
        vec!["sh".to_string(), "-c".to_string(), script.to_string()]
    }

    /// 共享的输出收集器：子进程输出线程写它，测试线程读它。
    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl SharedSink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("未被 poison").clone())
                .expect("测试输出应为 UTF-8")
        }
    }

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("未被 poison").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 按固定块大小产出的读端：用来精确控制"跨块"边界。
    struct Chunked {
        data: Vec<u8>,
        pos: usize,
        size: usize,
    }

    impl Read for Chunked {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let take = self
                .size
                .min(self.data.len().saturating_sub(self.pos))
                .min(buf.len());
            buf[..take].copy_from_slice(&self.data[self.pos..self.pos + take]);
            self.pos += take;
            Ok(take)
        }
    }

    fn pipe_to(
        script: &str,
        injection: &Injection,
        mask: bool,
    ) -> (i32, SharedSink, SharedSink) {
        let out = SharedSink::default();
        let err = SharedSink::default();
        let code = spawn_child(
            &sh(script),
            injection,
            ChildIo::Piped {
                mask,
                out: Box::new(out.clone()),
                err: Box::new(err.clone()),
            },
        )
        .expect("子进程应能启动");
        (code, out, err)
    }

    // ---- resolve：三种 `--with` 形态 --------------------------------------

    #[test]
    fn with_specs_support_all_three_forms() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = test_store(dir.path());
        let vault = fixture();

        let injection = resolve(
            &store,
            &vault,
            &specs(&[
                "OPENAI_API_KEY=akey://openai/credential",
                "DB_PW=db",
                "openai",
                "AUTH=Bearer akey://openai/credential",
                "my.api",
                "ORG=akey://openai/org",
            ]),
            &[],
            &[],
        )
        .expect("三种形态都应解析成功");

        let vars = var_map(&injection);
        assert_eq!(vars["OPENAI_API_KEY"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["ORG"], "org-acme");
        // `VAR=ITEM`：取该分类的默认秘密字段。
        assert_eq!(vars["DB_PW"], "db-password-SECRET");
        // 裸 `ITEM`：变量名由条目名派生。
        assert_eq!(vars["OPENAI"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["MY_API"], "sk-dotted-SECRET");
        // 引用嵌在字符串里时只替换引用本身。
        assert_eq!(vars["AUTH"], "Bearer sk-live-OPENAI-SECRET");
    }

    #[test]
    fn resolve_reports_bad_specs_and_missing_targets() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = test_store(dir.path());
        let vault = fixture();
        let resolve_one = |spec: &str| resolve(&store, &vault, &specs(&[spec]), &[], &[]);

        for bad in ["=value", "1BAD=value", "has space=value", "=akey://openai/credential"] {
            let err = resolve_one(bad).expect_err("非法变量名应被拒绝");
            assert_eq!(err.exit_code(), 2, "spec '{bad}': {err}");
            assert!(matches!(err, Error::Usage(_)), "spec '{bad}': {err:?}");
        }

        // env-bundle 没有"默认秘密字段"，裸引用必须引导到 `--bundle`。
        let err = resolve_one("deploy").expect_err("env-bundle 应被拒绝");
        assert!(matches!(err, Error::Usage(_)), "{err:?}");
        assert!(err.to_string().contains("--bundle deploy"), "{err}");

        // 不存在的条目 → not_found(3)。
        let err = resolve_one("nosuchitem").expect_err("条目不存在");
        assert_eq!(err.exit_code(), 3);
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");

        // 引用指向不存在的条目 → not_found，且点名引用原文。
        let err = resolve_one("X=akey://nosuchitem/credential").expect_err("引用未命中");
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("akey://nosuchitem/credential"), "{err}");

        // 引用嵌在字符串里时未命中，同样要点名引用而不是整个值。
        let err = resolve_one("X=Bearer akey://nosuchitem/credential").expect_err("引用未命中");
        assert!(err.to_string().contains("akey://nosuchitem/credential"), "{err}");

        // 条目在、字段不在 → not_found。
        let err = resolve_one("X=akey://openai/nosuchfield").expect_err("字段不存在");
        assert_eq!(err.exit_code(), 3);

        // 默认秘密字段缺失 → not_found（apikey 条目被删掉了 credential 字段）。
        let mut broken = fixture();
        let id = ulid(1);
        broken.entries.get_mut(&id).expect("条目存在").fields.clear();
        let err = resolve(&store, &broken, &specs(&["openai"]), &[], &[])
            .expect_err("缺字段应报错");
        assert_eq!(err.exit_code(), 3);
    }

    // ---- resolve：--bundle ------------------------------------------------

    #[test]
    fn bundle_injects_every_field_of_an_env_bundle() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = test_store(dir.path());
        let vault = fixture();

        let injection = resolve(&store, &vault, &[], &specs(&["deploy"]), &[]).expect("bundle 注入");
        let vars = var_map(&injection);

        assert_eq!(vars.len(), 3, "env-bundle 的全部字段都要注入");
        assert_eq!(vars["API_KEY"], "bundle-API-KEY-value");
        assert_eq!(vars["DB_HOST"], "db.internal");
        // 字段 slug 里的 `-` 折叠成 `_`，否则 shell 引用不到。
        assert_eq!(vars["CACHE_URL"], "redis://cache");
    }

    #[test]
    fn bundle_rejects_non_env_bundles_and_empty_bundles() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = test_store(dir.path());
        let mut vault = fixture();

        for item in ["openai", "db"] {
            let err = resolve(&store, &vault, &[], &specs(&[item]), &[]).expect_err("非 env-bundle");
            assert_eq!(err.exit_code(), 2, "{item}: {err}");
            assert!(err.to_string().contains("env-bundle"), "{err}");
        }

        let id = ulid(3);
        vault.entries.get_mut(&id).expect("条目存在").fields.clear();
        let err = resolve(&store, &vault, &[], &specs(&["deploy"]), &[]).expect_err("空 bundle");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("no fields"), "{err}");
    }

    // ---- --env-file：dotenv 解析 -----------------------------------------

    #[test]
    fn env_file_parses_dotenv_forms() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = test_store(dir.path());
        let vault = fixture();
        let path = env_file(
            dir.path(),
            ".env",
            concat!(
                "# 整行注释\n",
                "   # 缩进的注释\n",
                "\n",
                "export EXPORTED=exported-value\n",
                "export\tTAB_EXPORTED=tab-exported\n",
                "QUOTED=\"double quoted\"\n",
                "SINGLE='single quoted'\n",
                "WITH_EQUALS=a=b=c\n",
                "TRAILING=  spaced value  \n",
                "HASH=a#b\n",
                "EMPTY=\n",
                "ESCAPED=\"line1\\nline2\"\n",
                "REFERENCED=akey://openai/credential\n",
                "EMBEDDED=Bearer akey://openai/org\n",
            ),
        );

        let injection = resolve(&store, &vault, &[], &[], &[path]).expect("env-file 应解析成功");
        let vars = var_map(&injection);

        assert_eq!(vars["EXPORTED"], "exported-value");
        assert_eq!(vars["TAB_EXPORTED"], "tab-exported", "`export` 后的制表符同样是分隔符");
        assert_eq!(vars["QUOTED"], "double quoted");
        assert_eq!(vars["SINGLE"], "single quoted");
        assert_eq!(vars["WITH_EQUALS"], "a=b=c");
        assert_eq!(vars["TRAILING"], "spaced value");
        assert_eq!(vars["HASH"], "a#b", "行内 `#` 不是注释");
        assert_eq!(vars["EMPTY"], "");
        assert_eq!(vars["ESCAPED"], "line1\nline2");
        assert_eq!(vars["REFERENCED"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["EMBEDDED"], "Bearer org-acme");
    }

    #[test]
    fn dotenv_reports_syntax_errors_with_line_numbers() {
        let err = parse_dotenv(".env", "# ok\nGOOD=1\nBROKEN\n").expect_err("缺 `=`");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(".env:3"), "{err}");

        let err = parse_dotenv(".env", "1BAD=1\n").expect_err("非法名");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(".env:1"), "{err}");

        // 缺失的 env 文件 → io 错误（而不是静默当成空环境）。
        let dir = tempfile::tempdir().expect("临时目录");
        let err = load_env_file(&dir.path().join("nope.env")).expect_err("文件不存在");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("nope.env"), "{err}");
    }

    // ---- 优先级与排序 ----------------------------------------------------

    #[test]
    fn precedence_is_with_then_bundle_then_env_file_then_process_env() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = test_store(dir.path());
        let vault = fixture();
        let first = env_file(dir.path(), "first.env", "API_KEY=from-first-file\nONLY_FILE=first\n");
        let second = env_file(dir.path(), "second.env", "API_KEY=from-second-file\n");
        let files = vec![first, second];

        // 三个来源都提供 `API_KEY`：`--with` 最高。
        let injection = resolve(
            &store,
            &vault,
            &specs(&["API_KEY=akey://openai/credential"]),
            &specs(&["deploy"]),
            &files,
        )
        .expect("应解析成功");
        let vars = var_map(&injection);
        assert_eq!(vars["API_KEY"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["ONLY_FILE"], "first");

        // 去掉 `--with` → `--bundle` 胜出。
        let injection = resolve(&store, &vault, &[], &specs(&["deploy"]), &files).expect("应解析成功");
        let vars = var_map(&injection);
        assert_eq!(vars["API_KEY"], "bundle-API-KEY-value");
        // 多个 env 文件时后者覆盖前者。
        assert_eq!(vars["DB_HOST"], "db.internal");

        // 去掉 `--bundle` → env-file 胜出（后一个文件优先）。
        let injection = resolve(&store, &vault, &[], &[], &files).expect("应解析成功");
        let vars = var_map(&injection);
        assert_eq!(vars["API_KEY"], "from-second-file");
        assert_eq!(vars["ONLY_FILE"], "first");
    }

    #[test]
    fn injected_variables_override_the_process_environment() {
        let dir = tempfile::tempdir().expect("临时目录");
        // `HOME` 必然已在本进程环境里——这条测试的全部意义就是覆盖一个已存在的变量。
        let inherited = std::env::var("HOME").expect("测试进程应有 HOME");
        assert_ne!(inherited, "injected-home-value");

        let target = dir.path().join("out.txt");
        let injection = Injection {
            vars: vec![(
                "HOME".to_string(),
                Zeroizing::new("injected-home-value".to_string()),
            )],
        };
        let script = format!("/bin/echo -n \"$HOME\" > '{}'", target.display());
        let code = execute(&sh(&script), &injection, false).expect("子进程应能启动");
        assert_eq!(code, 0);
        assert_eq!(
            std::fs::read_to_string(&target).expect("读回子进程输出"),
            "injected-home-value",
            "注入变量必须压过继承来的环境变量"
        );
    }

    #[test]
    fn resolve_output_is_sorted_by_variable_name() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = test_store(dir.path());
        let vault = fixture();

        let forward = resolve(
            &store,
            &vault,
            &specs(&[
                "ZED=akey://openai/credential",
                "ALPHA=akey://openai/credential",
                "MID=akey://openai/org",
            ]),
            &[],
            &[],
        )
        .expect("应解析成功");
        let names: Vec<&str> = forward.vars.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["ALPHA", "MID", "ZED"]);

        let reversed = resolve(
            &store,
            &vault,
            &specs(&[
                "MID=akey://openai/org",
                "ZED=akey://openai/credential",
                "ALPHA=akey://openai/credential",
            ]),
            &[],
            &[],
        )
        .expect("应解析成功");
        assert_eq!(forward.vars, reversed.vars, "同一组输入必须得到同一份环境");
    }

    // ---- touch：授权面 ----------------------------------------------------

    #[test]
    fn touch_lists_reference_texts_items_and_subjects() {
        let dir = tempfile::tempdir().expect("临时目录");
        let vault = fixture();
        let path = env_file(
            dir.path(),
            ".env",
            "TOKEN=akey://openai/credential\nOTHER=akey://openai/org\n",
        );

        let surface = touch(
            &vault,
            &specs(&["OPENAI=akey://openai/credential", "db"]),
            &specs(&["deploy"]),
            &[path],
        )
        .expect("应能算出授权面");

        // 含引用的原文交给 `authorize_references`：spec 原文 + env 文件内容。
        assert_eq!(surface.texts.len(), 3);
        assert_eq!(surface.texts[0], "TOKEN=akey://openai/credential\nOTHER=akey://openai/org\n");
        assert_eq!(surface.texts[1], "OPENAI=akey://openai/credential");
        assert_eq!(surface.texts[2], "db", "裸条目原文也一并交给 authorize_references（其中没有引用）");
        // 不带引用的写法解析成条目名（用户传 ID 时也归一成名字）。
        assert_eq!(surface.items, vec!["db", "deploy"]);
        // 审计用：全部被触碰的条目名，去重升序。
        assert_eq!(surface.subjects, vec!["db", "deploy", "openai"]);

        // 传 ID 也要归一成条目名，否则作用域比对（比的是名字）会误判。
        let by_id = touch(
            &vault,
            &specs(&[&ulid(2).to_string()]),
            &[],
            &[],
        )
        .expect("应能算出授权面");
        assert_eq!(by_id.items, vec!["db"]);
    }

    // ---- render_template --------------------------------------------------

    #[test]
    fn render_template_replaces_every_reference() {
        let vault = fixture();
        let template = concat!(
            "key: akey://openai/credential\n",
            "org: akey://openai/org\n",
            "dup: akey://openai/credential\n",
            "plain: nothing to see\n",
        );
        assert_eq!(
            render_template(&vault, template).expect("应全部替换"),
            concat!(
                "key: sk-live-OPENAI-SECRET\n",
                "org: org-acme\n",
                "dup: sk-live-OPENAI-SECRET\n",
                "plain: nothing to see\n",
            )
        );

        assert_eq!(render_template(&vault, "no refs").expect("原样返回"), "no refs");
        assert_eq!(render_template(&vault, "").expect("空输入"), "");
    }

    #[test]
    fn render_template_names_unresolved_references() {
        let vault = fixture();

        let err = render_template(&vault, "token=akey://nosuchitem/credential")
            .expect_err("条目不存在");
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("akey://nosuchitem/credential"), "{err}");

        let err = render_template(&vault, "a\nakey://openai/nosuchfield\n").expect_err("字段不存在");
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
        assert!(err.to_string().contains("akey://openai/nosuchfield"), "{err}");
    }

    // ---- execute：退出码 --------------------------------------------------

    #[test]
    fn execute_passes_the_child_exit_code_through() {
        let injection = Injection::default();
        assert_eq!(execute(&sh("exit 0"), &injection, false).expect("启动"), 0);
        assert_eq!(execute(&sh("exit 42"), &injection, false).expect("启动"), 42);
        // 遮蔽模式同样透传退出码。
        assert_eq!(execute(&sh("exit 42"), &injection, true).expect("启动"), 42);
        assert_eq!(execute(&sh("exit 7"), &injection, true).expect("启动"), 7);
    }

    #[test]
    fn execute_maps_signals_to_128_plus_signal() {
        // SIGKILL 不可捕获，子进程必然死于信号。
        let code = execute(&sh("kill -9 $$"), &Injection::default(), false).expect("启动");
        assert_eq!(code, 128 + 9);
    }

    #[test]
    fn execute_without_a_command_is_a_usage_error() {
        let err = execute(&[], &Injection::default(), false).expect_err("没有命令");
        assert_eq!(err.exit_code(), 2);
    }

    // ---- execute：遮蔽 ----------------------------------------------------

    const SECRET: &str = "sk-live-MASK-ME-PLEASE-123456789";

    fn secret_injection() -> Injection {
        Injection {
            vars: vec![("SECRET".to_string(), Zeroizing::new(SECRET.to_string()))],
        }
    }

    #[test]
    fn piped_output_is_masked_and_never_leaks_the_plaintext() {
        let (code, out, err) = pipe_to(
            "printf 'token=%s\\n' \"$SECRET\"; printf 'err=%s\\n' \"$SECRET\" >&2",
            &secret_injection(),
            true,
        );
        assert_eq!(code, 0);

        let text = out.text();
        assert_eq!(text, format!("token={TAINTED}\n"));
        assert!(!text.contains(SECRET), "明文泄漏：{text}");
        let text = err.text();
        assert_eq!(text, format!("err={TAINTED}\n"));
        assert!(!text.contains(SECRET), "明文泄漏：{text}");
    }

    #[test]
    fn unmasked_output_passes_the_plaintext_through() {
        let (code, out, _) = pipe_to("printf %s \"$SECRET\"", &secret_injection(), false);
        assert_eq!(code, 0);
        assert_eq!(out.text(), SECRET, "不遮蔽时必须原样透出");
    }

    #[test]
    fn a_secret_split_across_reads_is_still_masked() {
        // 关键回归：密钥被任意切块（含 1 字节）时必须整体替换，不能漏出碎片。
        let text = format!("before {SECRET} after");
        for size in 1..=text.len() {
            let sink = SharedSink::default();
            relay(
                Chunked {
                    data: text.clone().into_bytes(),
                    pos: 0,
                    size,
                },
                Box::new(sink.clone()),
                vec![SECRET.to_string()],
                true,
            )
            .expect("泵入应成功");
            let rendered = sink.text();
            assert_eq!(rendered, format!("before {TAINTED} after"), "块大小 {size}");
            assert!(!rendered.contains(SECRET), "块大小 {size} 泄漏了明文");
        }
    }

    #[test]
    fn a_secret_written_in_pieces_by_a_child_is_still_masked() {
        // 子进程分多次写出、每次之间 sleep，把密钥拆成跨读块的碎片。
        let secret = "S3CRET-VALUE-THAT-IS-LONG";
        let pieces = ["S3CRE", "T-VAL", "UE-TH", "AT-IS", "-LONG"];
        assert_eq!(pieces.concat(), secret);
        // 每片都短于 MIN_SECRET_LEN：只有拼起来才够长，遮蔽必须靠跨块窗口。
        assert!(pieces.iter().all(|p| p.len() < crate::inject::mask::MIN_SECRET_LEN));

        let mut vars = vec![("SECRET".to_string(), Zeroizing::new(secret.to_string()))];
        for (index, piece) in pieces.iter().enumerate() {
            vars.push((format!("PIECE{index}"), Zeroizing::new((*piece).to_string())));
        }
        let script = "/bin/echo -n \"$PIECE0\"; sleep 0.05; /bin/echo -n \"$PIECE1\"; \
                      sleep 0.05; /bin/echo -n \"$PIECE2\"; sleep 0.05; \
                      /bin/echo -n \"$PIECE3\"; sleep 0.05; /bin/echo -n \"$PIECE4\"";

        let (code, out, _) = pipe_to(script, &Injection { vars }, true);
        assert_eq!(code, 0);
        assert_eq!(out.text(), TAINTED, "跨写块的密钥必须被整体遮蔽");
    }

    #[test]
    fn short_values_are_left_alone() {
        let injection = Injection {
            vars: vec![("FLAG".to_string(), Zeroizing::new("true".to_string()))],
        };
        let (code, out, _) = pipe_to("printf 'flag=%s' \"$FLAG\"", &injection, true);
        assert_eq!(code, 0);
        assert_eq!(out.text(), "flag=true", "短值不该被马赛克掉");
    }

    // ---- 辅助函数 ---------------------------------------------------------

    #[test]
    fn env_name_derives_shell_safe_names() {
        assert_eq!(env_name("openai"), "OPENAI");
        assert_eq!(env_name("my.api"), "MY_API");
        assert_eq!(env_name("cache-url"), "CACHE_URL");
        assert_eq!(env_name("API_KEY"), "API_KEY");

        for good in ["FOO", "_foo", "A1", "a_b"] {
            assert!(is_env_var_name(good), "{good}");
        }
        for bad in ["", "1FOO", "FOO-BAR", "FOO BAR", "FOO=BAR"] {
            assert!(!is_env_var_name(bad), "{bad}");
        }
    }
}
