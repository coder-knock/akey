# akey — 设计文档

> **English abstract.** Technical design for `akey`. §2 maps the module tree, §3 the Rust types,
> §4 the on-disk formats (`vault.age`, `recovery.age`, `recipients.json`), §5 the cryptographic
> layout, §6 the `akey://` reference grammar (EBNF), §7 the output-masking pipeline, §8 the sync
> algorithm, §9 the deterministic three-way merge, §10 the error taxonomy and exit codes, §12 the
> full command surface. The body is written in Chinese.

> 依据 `REQUIREMENTS.md` v0.2。开发顺序：**文档 → 测试 → 实现**；本文定义测试可断言的**全部接口与格式**。
> 名词：**条目** = entry（一个凭证）；**字段** = field；**引用** = reference URI。

---

## 1. 技术选型

| | 选择 | 理由 |
|---|---|---|
| 语言 | Rust 2024，`lib` + `bin` 双 target | 集成测试可直接调库；CLI 契约另用 `assert_cmd` 测 |
| 加密 | `age`（X25519 + ChaCha20-Poly1305；passphrase 模式为 scrypt） | 格式有公开规范、可被审计；不自造协议 |
| git | **子进程调用系统 `git`**，不引入 `gix` | 直接复用用户的 SSH key / credential helper / 代理；`gix` 的凭据链路不成熟 |
| CLI 框架 | `clap`(derive) + `clap_complete` | |
| 序列化 | `serde` + `serde_json` + `toml` | |
| 时间 | `chrono`（RFC3339） | |
| ID | `ulid`（26 位 Crockford base32，可按时间排序） | 稳定 ID，改名不断引用；天然有序 |

**依赖清单**（运行期）：`clap` `clap_complete` `serde` `serde_json` `toml` `age` `secrecy` `zeroize` `rand` `ulid` `base64` `sha2` `chrono` `totp-rs` `thiserror` `tempfile` `fd-lock` `rpassword`
**dev**：`assert_cmd` `predicates` `tempfile`

不引入：OpenSSL（`age` 用纯 Rust `rustls` 系组件）、`gix`、任何常驻 daemon。

## 2. 模块结构

```
src/
  main.rs            入口：解析 → 分发 → 退出码映射
  lib.rs             对外导出（供集成测试）
  cli.rs             clap 定义（唯一命令面真相源）
  error.rs           Error / code() / exit_code() / hint()
  output.rs          信封序列化 · stdout-stderr 纪律 · 遮蔽器 Masker
  paths.rs           AKEY_HOME / repo 解析 · 权限位 · 原子写
  config.rs          config.toml
  crypto/
    identity.rs      X25519 身份：生成 / 读写 / 0600 / 自解密
    boxcrypto.rs     多收件人加解密 · passphrase 加解密
    token.rs         能力令牌：生成 / SHA-256 校验 / 作用域
  vault/
    model.rs         Vault / Entry / Field / TokenMeta 类型
    store.rs         载入 / 保存 / 锁 / 加解密编排
    merge.rs         三方合并（纯函数，无 IO）
  reference.rs       引用解析与求值
  inject.rs          run / inject / 遮蔽管线
  sync/git.rs        git 子进程封装（fetch/show/commit/push/merge-base）
  audit.rs           append-only 日志
  cmd/*.rs           每个命令一个模块
tests/
  contract.rs        信封 / 退出码 / stdout-stderr
  reference.rs       引用解析表驱动
  merge.rs           三方合并表驱动
  crypto.rs          加密与令牌
  e2e_sync.rs        两设备同步 / 冲突 / 吊销
```

## 3. 数据模型

```rust
pub struct Vault {
    pub version: u32,                       // 1
    pub vault: String,                      // "default"
    pub entries: BTreeMap<Ulid, Entry>,      // 按 ID 有序
    pub tokens:  BTreeMap<Ulid, TokenMeta>,
    pub purged:  BTreeMap<Ulid, PurgedAt>,   // 防合并复活
}

pub struct Entry {
    pub id: Ulid,
    pub name: String,                        // ^[a-z0-9][a-z0-9._-]*$
    pub category: Category,
    pub title: Option<String>,
    pub fields: Vec<Field>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reveal: Reveal,                      // Allow | Deny（默认 Allow）
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,   // 软删；Some 即已删
}

pub struct Field {
    pub id: String,                          // 稳定 slug，引用用
    pub label: String,
    pub section: Option<String>,
    pub ty: FieldType,                       // String|Concealed|Email|Url|Otp|Date|Number|File|SshKey|Notes
    pub value: SecretString,                 // 永不进日志
}
impl Field { pub fn concealed(&self) -> bool }  // Concealed|Notes|SshKey → true

pub struct TokenMeta {
    pub id: Ulid, pub name: String, pub hash: String,   // base64(sha256(token))
    pub allow: Option<Vec<String>>,   // None = 全部（仍受 deny_reveal 约束）
    pub deny_reveal: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>, pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}
```
（无 salt 字段：令牌是 256 位随机值，盐对预映像攻击无增益。）

**ID 规则**：`Ulid::generate()`（48 位毫秒时间戳 + 80 位随机，26 位 Crockford base32）。名字可改，引用与审计锚定 ID。

## 4. 磁盘格式

### 4.1 `recipients.json`（公开，进 git）

```jsonc
{ "version": 1,
  "recipients": {
    "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgp…": {
      "name": "macbook", "kind": "device",   // device | bootstrap
      "added_at": "2026-09-19T02:00:00Z", "last_seen_at": "…", "revoked_at": null } } }
```

### 4.2 `vault.age` / `recovery.age`

- `vault.age`：`age` v1 **二进制**格式，收件人 = `recipients.json` 中未吊销公钥 **∩** 本机
  `config.toml` 的 `trusted` 集合。交集不可省：目录由不可信远端分发，它不能决定谁能解密。
- `recovery.age`：`age` passphrase 格式（scrypt），明文是
  `{"version":1,"bootstrap_identity":"AGE-SECRET-KEY-1…","created_at":"…"}`。
  仅在设置了恢复密码且**生成了引导身份**时存在。

### 4.3 `~/.config/akey/`

| 文件 | 内容 | 权限 |
|---|---|---|
| `identity.key` | `AGE-SECRET-KEY-1…` 单行 | `0600`，目录 `0700` |
| `config.toml` | `repo` · `remote` · `device_name` · `trusted` · `trust_seeded` | `0600` |
| `audit.log` | JSONL | `0600` |
| `vault.lock` | 空文件，仅用于加锁 | `0600` |

### 4.4 权限检查

`doctor` 与每次载入 vault 时校验：`identity.key` 与 `config.toml` 若 group/other 位非 0 → 警告（`doctor` 报 `insecure_permissions`）；`identity.key` 可被他人读 → 拒绝启动（退出码 4）。

## 5. 加密规格

```
身份        age X25519 密钥对（每设备一份，私钥永不进 git）
收件人       所有未吊销设备公钥 + 引导身份公钥
vault.age   age::Encryptor::with_recipients(recipients) 加密 vault JSON
解密        age::Decryptor::new(bytes) -> Recipients -> decrypt(本机身份)
换机引导      recovery.age 用恢复密码解出引导身份私钥 -> 用它解 vault.age
            -> 生成本机身份 -> 加入 recipients -> 重新加密 -> commit
令牌        随机 32 字节 -> base64url 展示一次；vault 只存 SHA-256 摘要
热路径成本   X25519 + ChaCha20-Poly1305（微秒级），无 KDF
KDF 时机     仅 init / init --from / recovery set|rotate（scrypt 由 age 内部完成）
```

**为什么令牌不用 Argon2id**：令牌是 256 位随机值，暴力搜索不可行，慢 KDF 在这里**没有安全收益**，
却会把每次 `akey run` 拖进几十毫秒。改用 SHA-256 + 常数时间比较——既快又足够。

`recovery.age` **不需要随 vault 更新**：它恒定包含"引导身份"，而引导身份始终是收件人之一。这是本设计的核心简化——换机引导不产生 staleness。

## 6. 引用语法

```ebnf
ref      = "akey://" [ vault "/" ] item [ "/" section ] "/" field [ "?" query ] ;
query    = param *( "&" param ) ;
param    = "attribute" "=" ( "value"|"otp"|"title"|"type"|"id" ) ;
vault    = seg ; item = seg ; section = seg ; field = seg ;
seg      = 1*( ALPHA | DIGIT | "-" | "_" | "." ) ;
```

**段内不允许空格**：引用要能在 env 文件与配置模板里被无引号扫描出来（见
`extract_references` 遇空白即停的规则），允许空格会让这两条路径互相矛盾。
需要空格的名字请用 `-` 或 `_`。

`ssh-format=openssh` 是 1Password CLI 的能力，本期未实现——`param` 里没有它，
传入会被当作未知参数名拒绝（`usage`）。

**求值顺序**
1. `$VAR` 展开（值取自当前进程 env；未定义 → `usage` 错误）
2. 按 `/` 切分；`vault` 省略时默认 `default`；`section` 省略时按字段名全局查找
3. `item` 先按 **ID** 精确匹配，再按 **name**；重名不可能（name 唯一）
4. 字段匹配大小写不敏感；歧义（同一 field 名出现在多个 section）→ `ambiguous`
5. `?attribute=otp` → 字段值须形如 `otpauth://…`，由 `totp-rs` 按给定时刻现算（6 位，30 秒窗口）；
   值不合法 → `usage`（错误消息里**不带**该值）

## 7. 遮蔽管线（`run`）

```
1. 汇总环境与 env-file 中的全部 akey:// 引用
2. 逐个求值 → Vec<(var, SecretString)>
3. 注入子进程 env（引用是纯环境变量时，值直接给出；引用嵌在别的字符串里时做替换）
4. 遮蔽（默认开）：
   - 只对长度 >= 8 的值启用，避免把 "true" / "0" 这类短串替换掉
   - stdout/stderr 走管道，`Masker` 逐块喂入
   - **窗口语义**：某位置 `i` 只有在 `i + max_secret_len <= 已收字节数`（即该位置的最长可能匹配已完整到达）
     时才下结论——先试最长匹配，命中则输出占位符并跳过该密钥长度，否则原样输出 1 字节。
     窗口未到齐就保留尾巴。
     （反例：若先试匹配再判断窗口，一块恰好停在较短密钥末尾时会立刻提交较短匹配，
      把较长密钥的尾巴原样漏出——最长匹配会失效。）
   - 命中替换为 <concealed by akey>
5. --no-masking → 三个 fd 全部 inherit（同时保留 TTY 语义，兼容交互式子进程）
6. 退出码透传子进程；子进程被信号杀死 → 128+signal
```

**已知取舍**：默认遮蔽用管道，会拿掉 TTY，交互式子进程（`vim`/`ssh`）须用 `--no-masking`。这是 1Password CLI 同样的取舍，文档显式写明。

## 8. 同步算法

```
sync():
  lock()
  if remote is none: return NoRemote
  git fetch --quiet
  local_rev = git rev-parse HEAD
  remote_rev = git rev-parse FETCH_HEAD
  match ancestry(local_rev, remote_rev):
    Equal        -> UpToDate
    LocalBehind  -> 快进工作区; Pulled(n)
    LocalAhead   -> push(); Pushed(n)
    Diverged     -> base  = decrypt(git show merge-base(local,remote):vault.age)
                    ours  = decrypt(工作区 vault.age)
                    theirs= decrypt(git show remote_rev:vault.age)
                    r = merge3(base, ours, theirs)
                    write(r.vault); commit("merge: N entries, M conflicts")
                    push()  // 非快进 → 重试至多 3 次，回第 2 步
```

`push()` 用 `git push`；非快进失败识别 stderr 中 `rejected` / `non-fast-forward`。

**冲突与退出码**：合并产生冲突副本时，提交与推送**已经成功**，但 `akey sync` 返回
`conflict`（退出码 5）并且**不往 stdout 写任何东西**——"失败的命令 stdout 为空"是对外契约，
不能因为"提交成功了"就破例。agent 从退出码察觉异常，再跑 `akey conflicts --json` 取详情。

## 9. 三方合并（纯函数）

签名：
```rust
pub fn merge3(base: &Vault, ours: &Vault, theirs: &Vault) -> MergeResult;
pub struct MergeResult { pub vault: Vault, pub conflicts: Vec<Conflict>, pub stats: MergeStats }
pub struct Conflict { pub id: Ulid, pub name: String, pub kind: ConflictKind,
                      pub ours_id: Ulid, pub theirs_id: Ulid, pub other_device: Option<String> }
```

规则（按条目 ID 对齐，**规则表见需求 §11.1**）。三个必须的工程约束：

1. **确定性**：合并输出对 `(base, ours, theirs)` 是纯函数。条目按 ID 排序；`updated_at` 取较新者（相等取 ours）。
2. **冲突条目 ID 必须可复现**：`theirs` 一侧被复制为 `<name>.conflict.<tag>` 时，新条目 ID 由
   `Ulid::from_bytes(sha256(id ‖ theirs.updated_at ‖ 字段值哈希)[..16])` 导出。
   → 两台设备独立合并同一分歧时算出**同一个 ID**，从而收敛，不会每轮同步再产出一个冲突副本。
3. **删除不比修改强**：`deleted_at` 是普通字段，不参与"胜出"，避免"一边删一边改"被静默丢弃。
   `rm --purge` 写 `purged[id] = ts`，合并时据此抑制复活；超过 90 天的墓碑在下次写入时清理。

## 10. 错误分类与退出码

```rust
pub enum Error {
    Usage(String),             // 2
    NotFound(String),          // 3
    Ambiguous(String),         // 3
    Locked(String),            // 4  无身份 / 解不开 / 令牌无效
    Conflict(Vec<Conflict>),   // 5
    SyncFailed(String),        // 6
    Denied(String),            // 7  reveal 被策略拒
    TokenScope(String),        // 8  令牌越权
    Io(..) | Crypto(..) | Corrupt(String) | Git(..) | Unsupported(String),  // 1
}
```

JSON 错误体：`{"ok":false,"error":{"code":"not_found","message":"…","hint":"…"}}`
`code` 为 `snake_case` 稳定标识（`usage` `not_found` `ambiguous` `locked` `conflict` `sync_failed` `denied` `token_scope` `io` `crypto` `corrupt` `git` `unsupported`）。

## 11. 并发与原子性

- 全局写锁：`~/.config/akey/vault.lock`，`fd-lock` 排他，获取超时 10s → `locked`。
- 读命令只取共享锁。
- 任何落盘走 `paths::atomic_write`：同目录临时文件 → `fsync(file)` → `rename` → `fsync(dir)`。
- `vault.age` 与 `recipients.json` 的更新同属一次事务：先写临时文件，全部成功后再 rename，失败则不留半成品。

## 12. 命令面（`cli.rs` 唯一真相源）

```
akey [全局标志] <命令>

全局: --json | --format human|json | --no-color | --quiet | --debug
      --home <dir> | --repo <path> | --token <t> | --yes | --dry-run

init      [--repo P] [--remote URL] [--from URL] [--device NAME] [--recovery|--no-recovery]
read      <ref> [--out-file F] [--no-newline]
run       [--with ITEM]... [--env-file F]... [--no-masking] -- <cmd> [args...]
inject    [-i F] [-o F]
get       <item> [--fields L]... [--reveal] [--otp]
set       <item> [<assign>...] [--category K] [--title T] [--tags L] [--template F] [--stdin] [--generate-password[=recipe]]
edit      <item> [<assign>...] [--title T] [--tags L] [--template F] [--favorite] [--rotate]
rm        <item>... [--purge]
restore   <item>...
cp        <src> <dst> ;  mv <old> <new>
list      [--tags L] [--category K] [--expiring DUR] [--favorite] [--all] [--reveal? no]
template  list | get <category> [--out-file F]
doc       get <ref> [--out-file F] | put <item> <file>
token     create --name N [--allow L] [--deny-reveal] [--ttl DUR] | list | rm <name>
devices   list | add [--name N] | rm <name> | rename <old> <new>
recovery  set | rotate | unlock
sync      [--push|--pull|--status]
conflicts [--json]
resolve   <name> --ours | --theirs
log       [--since DUR] [--item NAME] [--limit N]
whoami
doctor    [--agent]
schema    [--format json]
completion <bash|zsh|fish|powershell>
export    --format json|dotenv|csv1p [--out-file F] --yes
import    --format … [-i F] [--merge]
mcp
```

**赋值语句**：`[<section>.]<field>[[<type>]]=<value>`；`<field>` 为已存在字段时改值，否则新建。值为空 → `[delete]` 删除自定义字段。秘密值走 argv 时打印警告并提示用 `--stdin` / `--template`。

**`set --stdin`**：从 stdin 读两种形态之一——多行 `field=value`，或**一段裸秘密值**
（此时写入 `--secret-field` 或该分类的默认秘密字段）。不支持 JSON 输入。
这样秘密不进 argv，也就不会出现在 shell 历史与 `ps` 输出里。

**`read` 没有 `--reveal`**：它本身就是显式的明文通道，因此直接受 `gate_reveal`
（条目 `reveal` 策略 / `AKEY_NO_REVEAL` / 令牌 `--deny-reveal`）约束；再叠一层 `--reveal`
只是仪式感。`get` 才是默认隐藏、需要 `--reveal` 展开的那个。

## 13. `akey schema` 契约

输出机器可读清单，供 agent 自举：`{name, version, global_flags[], env_vars[], exit_codes{}, reference{grammar, examples[]}, commands[{name, summary, args[], flags[], examples[]}]}`。测试断言其为合法 JSON 且含全部必需键。

## 14. 实现顺序（测试先行）

1. `crypto`（含 `token`）→ 单测
2. `vault/model` + `store` + `paths` → 单测（原子写、权限）
3. `reference` → 表驱动单测
4. `vault/merge` → 表驱动单测（含确定性、冲突 ID 可复现）
5. `output` + `error` + `cli` 骨架 → 契约测试
6. `inject` → 单测（遮蔽、跨块、短值不遮蔽）+ 集成测试
7. `sync/git` → e2e（两个临时 repo）
8. 其余命令 → 集成测试
9. `AGENTS.md` + `doctor` + `schema`

## 15. 风险

| 风险 | 处理 |
|---|---|
| `age` crate API 变动 | 锁定 minor 版本；加解密路径有固定向量测试 |
| 遮蔽的跨块漏配 | 滑动窗口 + 专项测试（构造 1 字节分块） |
| git 凭据差异（HTTPS/SSH） | 复用系统 `git`，不自实现；`doctor` 探测 `git ls-remote` |
| 单文件密文的合并语义 | `merge3` 是纯函数，规则表全量单测；冲突 ID 可复现 |
| 大 vault 热路径性能 | NFR-2 有基准；单文件读写在 10⁴ 条目内 < 10ms |
