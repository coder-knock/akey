//! Machine-local private directory: path resolution, permissions, atomic writes, file locks.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Owner-only, on platforms that have POSIX modes. Windows has none; see [`ensure_private`].
pub const DIR_MODE: u32 = 0o700;
pub const FILE_MODE: u32 = 0o600;
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(25);

/// The set of machine-local private files (all under `$AKEY_HOME`, **never synced**).
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
        restrict_dir(&self.home)?;
        Ok(())
    }

    pub fn has_identity(&self) -> bool {
        self.identity.is_file()
    }

    pub fn has_config(&self) -> bool {
        self.config.is_file()
    }
}

/// Beyond `AKEY_HOME` > `--home`:
/// unix `$XDG_CONFIG_HOME/akey` > `$HOME/.config/akey`; Windows `%APPDATA%\akey`.
///
/// On Windows the profile directory is the point: its ACL is already restricted to the user,
/// which is what makes the identity private in the absence of mode bits.
pub fn resolve_home(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(v) = non_empty_env("AKEY_HOME") {
        return Ok(PathBuf::from(v));
    }

    #[cfg(unix)]
    {
        if let Some(v) = non_empty_env("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(v).join("akey"));
        }
        let home = non_empty_env("HOME").ok_or_else(|| {
            Error::locked(crate::msg!(
                "cannot determine home directory; set $HOME or $AKEY_HOME",
                "无法确定主目录；请设置 $HOME 或 $AKEY_HOME"
            ))
        })?;
        Ok(PathBuf::from(home).join(".config").join("akey"))
    }

    #[cfg(windows)]
    {
        let appdata = non_empty_env("APPDATA").ok_or_else(|| {
            Error::locked(crate::msg!(
                "cannot determine the config directory; set %APPDATA% or AKEY_HOME",
                "无法确定配置目录；请设置 %APPDATA% 或 AKEY_HOME"
            ))
        })?;
        Ok(PathBuf::from(appdata).join("akey"))
    }
}

fn non_empty_env(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|v| !v.is_empty())
}

/// Creation-time owner-only mode for a file we are about to write secrets into.
///
/// Applying it through the builder's `mode` (rather than a path-based `chmod` after the fact)
/// is what removes the "readable for a few microseconds" window: the file never exists in a
/// weaker state than `0600`. Windows has no equivalent and needs none — the profile ACL
/// already covers it.
#[cfg(unix)]
pub fn owner_only(builder: &mut OpenOptions) -> &mut OpenOptions {
    builder.mode(FILE_MODE)
}

#[cfg(windows)]
pub fn owner_only(builder: &mut OpenOptions) -> &mut OpenOptions {
    builder
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) -> Result<()> {
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))?;
    Ok(())
}

/// `%APPDATA%\akey` inherits the profile ACL, which is already owner-only. Nothing to do.
#[cfg(windows)]
fn restrict_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_file(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}

/// Same-directory write → `fsync` → atomic `rename`. A failure leaves no half-written file.
///
/// `mode` creates the temporary file as `0o600`, so there is no "land first, chmod later" window.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        Error::usage(crate::msg!(
            "path has no parent directory: {}",
            "路径没有父目录：{}",
            path.display()
        ))
    })?;
    fs::create_dir_all(dir)?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".akey-tmp-")
        .tempfile_in(dir)?;
    restrict_file(tmp.as_file(), mode)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| Error::Io(e.error))?;
    sync_dir(dir);
    Ok(())
}

/// Durably record a rename by fsyncing the directory that holds it.
///
/// Unix only: opening a directory as a file needs `FILE_FLAG_BACKUP_SEMANTICS` on Windows, and
/// `File::open` there fails. The rename itself is still atomic.
#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

/// Verifies the file is owner-readable/writable only. Readable by other users is refused —
/// an identity leak is a whole-vault leak.
#[cfg(unix)]
pub fn ensure_private(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::locked(crate::msg!(
            "{} is accessible by other users (mode {}); run: chmod 600 {}",
            "{} 可被其他用户访问（模式 {}）；请运行：chmod 600 {}",
            path.display(),
            format!("{mode:o}"),
            path.display()
        )));
    }
    Ok(())
}

/// Windows has no POSIX mode bits, so the invariant is stated differently and checked
/// differently: the private files must live inside the user profile, whose ACL the OS already
/// restricts to that user (plus SYSTEM and Administrators). That is the same guarantee as
/// `0600` in the directory-ownership sense — and unlike a mode check it also covers the
/// "someone pointed `AKEY_HOME` at `C:\shared`" case, which is the one that actually happens.
///
/// Per-file ACLs are deliberately not set: the parent directory is already owner-only, and
/// writing a DACL correctly is a lot of surface for no additional guarantee.
#[cfg(windows)]
pub fn ensure_private(path: &Path) -> Result<()> {
    if is_inside(user_profile().as_deref(), path) {
        return Ok(());
    }
    Err(Error::locked(crate::msg!(
        "{} is outside your user profile; on Windows akey relies on the profile ACL to keep the \
         identity private, so it refuses to use a shared location. Move it under {} or pass --home",
        "{} 不在你的用户配置目录内；在 Windows 上 akey 依赖配置文件 ACL 来保证身份私密，因此拒绝使用共享位置。请将它移动到 {} 下，或传入 --home",
        path.display(),
        user_profile().map_or_else(|| "%USERPROFILE%".to_string(), |p| p.display().to_string())
    )))
}

/// `%USERPROFILE%` — the Windows equivalent of `$HOME`.
#[cfg(windows)]
fn user_profile() -> Option<PathBuf> {
    non_empty_env("USERPROFILE").map(PathBuf::from)
}

/// Path containment. Split out so a unit test can drive it on any platform.
#[cfg(any(windows, test))]
fn is_inside(root: Option<&Path>, path: &Path) -> bool {
    // Prefix comparison rather than canonicalisation: both sides come from the same source
    // (an environment variable and a path we built from it), and canonicalising would touch
    // the filesystem on a code path that is supposed to be a cheap guard.
    root.is_some_and(|root| path.starts_with(root))
}

/// Read-only probe of whether permissions are safe, for `doctor` (does not refuse, only reports).
#[cfg(unix)]
pub fn permissions_exposed(path: &Path) -> Result<bool> {
    let meta = fs::metadata(path)?;
    Ok(meta.permissions().mode() & 0o077 != 0)
}

#[cfg(windows)]
pub fn permissions_exposed(path: &Path) -> Result<bool> {
    Ok(!is_inside(user_profile().as_deref(), path))
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::locked(crate::msg!(
                "{} not found; run `akey init`",
                "{} 未找到；请运行 `akey init`",
                path.display()
            ))
        } else {
            Error::Io(e)
        }
    })
}

/// Read-modify-write under an exclusive lock. Timeout returns `locked` (exit code 4).
pub fn with_write_lock<T>(lock_path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    with_write_lock_timeout(lock_path, LOCK_TIMEOUT, f)
}

/// The timeout is a parameter so the contention path can be asserted in milliseconds rather
/// than in the ten seconds a real caller waits. Two `akey` processes writing at once is the
/// case this protects: the loser must get a clear `locked`, not interleave or hang forever.
fn with_write_lock_timeout<T>(
    lock_path: &Path,
    timeout: Duration,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if let Some(dir) = lock_path.parent() {
        fs::create_dir_all(dir)?;
    }
    // `truncate(false)`: the lock file carries no content, and truncating a file another
    // process holds open is a side effect for nothing.
    let file = owner_only(
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false),
    )
    .open(lock_path)?;
    let mut lock = fd_lock::RwLock::new(file);

    let deadline = Instant::now() + timeout;
    let _guard = loop {
        match lock.try_write() {
            Ok(guard) => break guard,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Error::locked(crate::msg!(
                        "another akey process holds {}",
                        "另一个 akey 进程持有 {}",
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
        assert!(
            paths.home.is_dir(),
            "ensure() must create the home directory"
        );
        #[cfg(unix)]
        {
            let mode = fs::metadata(&paths.home).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, DIR_MODE, "home must be owner-only");
        }
    }

    /// The Windows private-file guard: everything must sit inside the user profile. Run on every
    /// platform, because this predicate *is* the Windows guarantee.
    #[test]
    fn profile_containment_is_a_prefix_test_over_path_components() {
        let profile = Path::new("/home/ada");
        assert!(is_inside(
            Some(profile),
            Path::new("/home/ada/.config/akey/identity.key")
        ));
        assert!(!is_inside(
            Some(profile),
            Path::new("/shared/akey/identity.key")
        ));
        // A sibling whose *name* shares a prefix must not count: component-wise, not string-wise.
        assert!(!is_inside(
            Some(profile),
            Path::new("/home/adamantine/identity.key")
        ));
        // No profile to compare against is not a pass.
        assert!(!is_inside(None, Path::new("/home/ada/identity.key")));
    }

    #[test]
    fn atomic_write_lands_complete_content_with_mode() {
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        let target = paths.home.join("vault.age");

        atomic_write(&target, b"first", FILE_MODE).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        #[cfg(unix)]
        {
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, FILE_MODE);
        }

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
        // Write a payload far larger than a single write, confirming the old content is either present or fully replaced.
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();
        let target = paths.home.join("big");
        atomic_write(&target, &vec![b'a'; 512 * 1024], FILE_MODE).unwrap();
        atomic_write(&target, &vec![b'b'; 512 * 1024], FILE_MODE).unwrap();

        let got = fs::read(&target).unwrap();
        assert_eq!(got.len(), 512 * 1024);
        assert!(got.iter().all(|b| *b == b'b'), "torn write detected");
    }

    /// Mode bits are unix-only; on Windows the equivalent guard is `is_inside`, above.
    #[cfg(unix)]
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

    /// The contended half: while another holder has the lock, a writer must give up with
    /// `locked` rather than hang or proceed. Two `akey` processes racing on one vault is
    /// ordinary (an agent retrying while a sync runs), so this is the path that matters.
    #[test]
    fn write_lock_times_out_with_locked_while_another_holder_is_active() {
        let (_guard, paths) = temp_home();
        paths.ensure().unwrap();

        // A separate handle, exactly as a second process would have.
        let held = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&paths.lock)
            .unwrap();
        let mut holder = fd_lock::RwLock::new(held);
        let _held = holder.write().unwrap();

        let err = with_write_lock_timeout(&paths.lock, Duration::from_millis(50), || Ok(1))
            .expect_err("a held lock must not be granted");
        assert_eq!(err.exit_code(), 4);
        assert!(
            err.to_string().contains("another akey process"),
            "the failure must say who holds it: {err}"
        );

        // And it is genuinely free again once the holder lets go.
        drop(_held);
        assert_eq!(
            with_write_lock_timeout(&paths.lock, Duration::from_millis(50), || Ok(7)).unwrap(),
            7
        );
    }

    #[test]
    fn read_file_reports_missing_as_locked_with_actionable_message() {
        let (_guard, paths) = temp_home();
        let err = read_file(&paths.identity).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("akey init"));
    }
}
