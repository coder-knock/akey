//! 本机私有目录：路径解析、权限、原子写、文件锁。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

pub const DIR_MODE: u32 = 0o700;
pub const FILE_MODE: u32 = 0o600;
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(25);

/// 本机私有文件集合（全部在 `$AKEY_HOME` 下，**永不同步**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub home: PathBuf,
    pub identity: PathBuf,
    pub config: PathBuf,
    pub audit: PathBuf,
    pub lock: PathBuf,
}

impl Paths {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Paths {
            identity: home.join("identity.key"),
            config: home.join("config.toml"),
            audit: home.join("audit.log"),
            lock: home.join("vault.lock"),
            home,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.home)?;
        fs::set_permissions(&self.home, fs::Permissions::from_mode(DIR_MODE))?;
        Ok(())
    }

    pub fn has_identity(&self) -> bool {
        self.identity.is_file()
    }

    pub fn has_config(&self) -> bool {
        self.config.is_file()
    }
}

/// `AKEY_HOME` > `--home` 之外：`$XDG_CONFIG_HOME/akey` > `$HOME/.config/akey`。
pub fn resolve_home(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(v) = non_empty_env("AKEY_HOME") {
        return Ok(PathBuf::from(v));
    }
    if let Some(v) = non_empty_env("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(v).join("akey"));
    }
    let home = non_empty_env("HOME").ok_or_else(|| {
        Error::locked("cannot determine home directory; set $HOME or $AKEY_HOME")
    })?;
    Ok(PathBuf::from(home).join(".config").join("akey"))
}

fn non_empty_env(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|v| !v.is_empty())
}

/// 同目录写入 → `fsync` → 原子 `rename`。失败不留半成品。
///
/// `mode` 以 `0o600` 建立临时文件，因此不存在"先落地再 chmod"的窗口。
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        Error::usage(format!("path has no parent directory: {}", path.display()))
    })?;
    fs::create_dir_all(dir)?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".akey-tmp-")
        .tempfile_in(dir)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| Error::Io(e.error))?;
    sync_dir(dir);
    Ok(())
}

fn sync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// 校验文件只有属主可读写。其他用户可读时拒绝——身份泄露即整库泄露。
pub fn ensure_private(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::locked(format!(
            "{} is accessible by other users (mode {mode:o}); run: chmod 600 {}",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

/// 只读地探测权限是否安全，供 `doctor` 使用（不拒绝，只报告）。
pub fn permissions_exposed(path: &Path) -> Result<bool> {
    let meta = fs::metadata(path)?;
    Ok(meta.permissions().mode() & 0o077 != 0)
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::locked(format!("{} not found; run `akey init`", path.display()))
        } else {
            Error::Io(e)
        }
    })
}

/// 排他锁下的读-改-写。超时返回 `locked`（退出码 4）。
pub fn with_write_lock<T>(lock_path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    if let Some(dir) = lock_path.parent() {
        fs::create_dir_all(dir)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(FILE_MODE)
        .open(lock_path)?;
    let mut lock = fd_lock::RwLock::new(file);

    let deadline = Instant::now() + LOCK_TIMEOUT;
    let _guard = loop {
        match lock.try_write() {
            Ok(guard) => break guard,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Error::locked(format!(
                        "another akey process holds {}",
                        lock_path.display()
                    )));
                }
                std::thread::sleep(LOCK_POLL);
            }
            Err(e) => return Err(Error::Io(e)),
        }
    };

    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("akey"));
        (dir, paths)
    }

    #[test]
    fn home_resolution_prefers_explicit_then_env() {
        let explicit = Path::new("/tmp/explicit-akey");
        assert_eq!(resolve_home(Some(explicit)).unwrap(), explicit);
    }

    #[test]
    fn ensure_creates_private_home() {
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        let mode = fs::metadata(&paths.home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, DIR_MODE, "home must be owner-only");
    }

    #[test]
    fn atomic_write_lands_complete_content_with_mode() {
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        let target = paths.home.join("vault.age");

        atomic_write(&target, b"first", FILE_MODE).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, FILE_MODE);

        atomic_write(&target, b"second", FILE_MODE).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_leaves_no_temp_files_behind() {
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        atomic_write(&paths.home.join("x"), b"data", FILE_MODE).unwrap();

        let leftovers: Vec<_> = fs::read_dir(&paths.home)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".akey-tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    #[test]
    fn replacing_a_file_never_exposes_a_partial_state() {
        // 写入一个远大于单次 write 的负载，确认旧内容要么在、要么被完整替换。
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        let target = paths.home.join("big");
        atomic_write(&target, &vec![b'a'; 512 * 1024], FILE_MODE).unwrap();
        atomic_write(&target, &vec![b'b'; 512 * 1024], FILE_MODE).unwrap();

        let got = fs::read(&target).unwrap();
        assert_eq!(got.len(), 512 * 1024);
        assert!(got.iter().all(|b| *b == b'b'), "torn write detected");
    }

    #[test]
    fn ensure_private_rejects_group_readable_file() {
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        atomic_write(&paths.identity, b"secret", 0o644).unwrap();

        let err = ensure_private(&paths.identity).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(matches!(err, Error::Locked(_)));

        fs::set_permissions(&paths.identity, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        ensure_private(&paths.identity).unwrap();
        assert!(!permissions_exposed(&paths.identity).unwrap());
    }

    #[test]
    fn write_lock_serialises_and_runs_closure() {
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        let out = with_write_lock(&paths.lock, || Ok(41 + 1)).unwrap();
        assert_eq!(out, 42);
    }

    #[test]
    fn read_file_reports_missing_as_locked_with_actionable_message() {
        let (_guard, paths) = temp_home();
        let err = read_file(&paths.identity).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("akey init"));
    }
}
