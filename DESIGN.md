# akey — 设计文档

> **English abstract.** Technical design for `akey`. §2 maps the module tree, §3 the Rust types,
> §4 the on-disk formats (`vault.age`, `recovery.age`, `recipients.json`), §5 the cryptographic
> layout, §6 the `akey://` reference grammar (EBNF), §7 the output-masking pipeline, §8 the sync
> algorithm, §9 the deterministic three-way merge, §10 the error taxonomy and exit codes, §12 the
> full command surface. The body is written in Chinese.

> 依据 `REQUIREMENTS.md` v0.2。开发顺序：**文档 → 测试 → 实现**；本文定义测试可断言的**全部接口与格式**。
> 名词：**条目** = entry（一个凭证）；**字段** = field；**引用** = reference URI。
>
> 可视化：三张可交互图（架构 / `sync` 流程 / `run` 时序）在 [`docs/diagrams/`](docs/diagrams/)，
> 均为独立 HTML，浏览器直接打开；每张由同名 JSON 规格生成，见 README 的「图表」一节。

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
  i18n.rs            en / zh-CN 文案 · 语言判定
  agents_md.rs       金库仓库自带的 AGENTS.md
  crypto/
    identity.rs      X25519 身份：生成 / 读写 / 0600 / 自解密
    boxcrypto.rs     多收件人加解密 · passphrase 加解密
    token.rs         能力令牌：生成 / SHA-256 校验 / 作用域
  vault/
    model.rs         Vault / Entry / Field / TokenMeta 类型
    store.rs         载入 / 保存 / 锁 / 加解密编排
    merge.rs         三方合并（纯函数，无 IO）
    generator.rs     Password / passphrase 生成
    migrate.rs       金库格式前向迁移
    recipients.rs    recipients.json（仅公钥）
  reference.rs       引用解析与求值
  inject/
    mod.rs           run / inject 编排
    run.rs           环境装配 + 子进程执行
    mask.rs          子进程输出的流式遮蔽
  sync/
    mod.rs           同步 / 冲突 / 合并编排
    git.rs           git 子进程封装（fetch/show/commit/push/merge-base）
  audit.rs           append-only 日志
  cmd/*.rs           每个命令一个模块
  cmd/deliver/
    mod.rs           命令出口 · 共享 IO helper
    handoff.rs       read / run / inject
    export.rs        export
    import.rs        import
    doc.rs           doc get / put
    mcp.rs           mcp JSON-RPC
    tests.rs         命令层测试
  cmd/entries/
    mod.rs           命令出口 · 共享错误映射
    read.rs          get / list
    write.rs         set / edit
    input.rs         赋值解析 · stdin · 密码生成
    template.rs      template · --template
    lifecycle.rs     rm / restore / cp / mv
    conflict.rs      conflicts / resolve
    tests.rs         命令层测试
  cmd/admin/
    mod.rs           命令出口 · 共享 Git / 错误 helper
    init.rs          init（新建 / 接入远端）
    devices.rs       devices（信任 / 撤销）
    passphrase.rs    恢复密码获取与长度策略
    recovery.rs      recovery（设置 / 解锁 / 轮换）
    token.rs         token（能力令牌）
    diagnostics.rs   whoami / doctor
    reference.rs     log / schema / completion
    tests.rs         命令层测试
  agent/
    registry.rs      harness 表：作用域 / 配置文件 / skill 根 / 原生 CLI
    config.rs        配置流水线：匹配 · 规划 · 原子写 · 按格式分发
    config/
      json.rs        JSON/JSONC 适配（CST，保留注释）
      toml.rs        TOML 适配（toml_edit）
      yaml.rs        YAML 适配（yaml_edit）
      tests.rs       配置适配测试
    skill.rs         内嵌 SKILL.md · sidecar 记账 · --force 语义
    selection.rs     默认 / 显式选择规则
    native.rs        原生 CLI 查找 · 调用 · 失败诊断
    install.rs       安装生命周期 + 报告
    uninstall.rs     卸载生命周期 + 报告
    inspect.rs       list / status / print
    mod.rs           模块出口 · 重导出 · display_path
    tests.rs         harness 测试
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
agent     list | status [AGENT]...
          | install [AGENT]... | --all [--force] [--no-native]
          | uninstall [AGENT]... | --all [--force]
          | print [AGENT]...
          # status/install/uninstall/print 接受 --scope 与 --only；
          # install 另有 --force/--no-native，uninstall 另有 --force
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

---

## 16. 国际化

**只本地化人类可读文本。`--json` 在任何语言下逐字节相同**——agent 依赖 `error.code` 与稳定键名，不依赖散文。

### 16.1 语言解析

优先级：`--lang` > `$AKEY_LANG` > `$LC_ALL` > `$LC_MESSAGES` > `$LANG` > `en`。

- 标签只按**主子标签**匹配：`zh`、`zh_CN.UTF-8`、`zh-Hans-CN`、`ZH-cn` 都落到 `zh-CN`；`en-*` 落到 `en`。
- 显式 `--lang` 指向不支持的语言 → 退出 2（**不静默降级**）：用户既然点名了，就该被告知。
- 环境变量里的 locale 指向不支持的语言 → 回退 `en`，不是错误：世界上大多数 locale 并不是一个具体请求。
- 解析发生在 **clap 解析之前**：`--help` 正是那次解析的产物，所以语言必须先定。`--lang` 因此被预扫一次（`i18n::lang_from_argv`），这是它被读两遍的唯一原因。

### 16.2 消息表示

```rust
pub struct Msg { en: &'static str, zh_cn: &'static str }
```

消息是**值**而不是按 key 查表：一条消息只要存在，就在所有语言里存在。因此不存在「缺翻译」这种状态，也不存在会失效的 key。

`msg!(en, zh, args…)` 与 `format!` 同形，占位符为 `{}`；`i18n::m(en, zh)` 是给 clap 属性用的简写（clap 在构建命令树时求值，所以属性里写表达式即可运行时本地化，不必把 derive 改写成 builder）。

**占位符数量在编译期校验**（`msg!` 内联 `const` 断言）：翻译少写一个 `{}` 会吞掉一个参数、多写一个会印出裸占位符，两者都是编译错误。

### 16.3 覆盖状态

| 面 | 状态 |
|---|---|
| 帮助文本（`cli.rs`，clap 属性） | 全量双语 |
| `Error::hint()`（6 条） | 全量双语 |
| 错误消息正文 | 英文完整；中文待补——缺翻译时回退英文，不会缺失 |
| 人类成功输出（`emit` 的首参）、告警、`--debug` 标签、`error:`/`warning:`/`hint:` 框架 | 全量双语 |
| clap 内建的 `Usage:` / `Options:` 等标签 | clap 自绘，两语言下都是英文（上游无本地化） |

**`--json` 不变式的唯一例外**：`akey schema` 的 `summary` 与 `args[].help` 就是 `--help` 的字符串，因此随 `--lang` 变化。其余所有载荷（`list`／`get`／`doctor`／`whoami`／`devices list`／各 dry-run）逐字节稳定，由 `contract::language_changes_human_text_and_leaves_the_json_contract_untouched` 钉住。

---

## 17. 本地密码管理：生成器、审计、`Password` 一等分类

这一节把 `akey` 围绕「密码」这一最常见秘密类型的工作面做厚。不引入新的 daemon、新的服务端、不改变 `recipients.json ∩ trusted` 的加密门。改动只发生在：生成器 / 恢复密码 UX / `doctor` 的若干检查项 / 一个新的 `Category::Password`。

### 17.1 生成器配方语法

```
recipe   ::= token *( "," token )      # 顺序无关
token    ::= "letters" | "digits" | "symbols"
          | "no-ambiguous"             # 0/O/1/l/I/| 不参与
          | "hex" | "base32" | "base64"
          | "passphrase"               # 见 17.2
          | <length: 1..=4096>
```

空字符串 = `letters,digits,symbols,32`（向后兼容现有 `--generate-password`）。

字符集 `pool`：

| Token        | 字符集 |
|---|---|
| `letters`    | `a-z` ∪ `A-Z` (52) |
| `digits`     | `0-9` (10) |
| `symbols`    | `!@#$%^&*()-_=+[]{};:,.<>/?~` (28) |
| `no-ambiguous` | 从当前池中剔除 `0 O o O 1 l I |` 后剩下的字符 |
| `hex`        | `0-9a-f` (16) |
| `base32`     | Crockford base32 字母表 (32) |
| `base64`     | `A-Za-z0-9+/` (64) |

`token` 之间以 OR 语义合并池；多 token = 多个池取并集。`passphrase` 与其它 token 互斥，**不能** 同时出现——给出 `passphrase,<n>` 时 `<n>` 是词数（默认 5），其余 token 一律拒（exit 2）。

**采样**：从 CSPRNG 一次性取够字节，按 256 → pool_size 的模映射回池；模偏置通过 `limit = 256 - (256 % size)` 拒绝均匀化（已是 `entries/input.rs::password_from_bytes` 的现有实现，扩展时不动它，只把 `pool` 的生成抽到一个新模块 `vault::generator::pool_for`）。

### 17.2 Diceware 词表

`passphrase` 配方使用内置 **EFF 短词表**（~1296 词，CC-BY-SA 3.0）。二进制体积增加 ~10 KB。无运行时网络访问。

- 词数：1..=10（默认 5）；entropy ≈ log₂(1296ⁿ) = 10.34·n 比特。
- 分隔符：固定 `-`，5 词 ≈ 51.7 比特（与 `--generate-password letters,digits,symbols,32` 的 ~190 比特不在同一量级——明确告诉用户：词组更适合记，不适合机机接口）。
- 词表来源在 `assets/diceware/eff-short.txt` 随源码分发；构建期 `include_str!` 嵌入。`tests::wordlist_is_nonempty_and_lowercase` 钉住词数 ≥ 1024、全小写、无重复。

### 17.3 强度评分

`recovery status` 与 `akey audit` 用同一份长度启发式（不假装是熵估计——DESIGN.md 不写熵）：

| 长度 | 等级 |
|---|---|
| < 8  | too-short |
| 8..=11 | weak |
| 12..=15 | fair |
| 16..=23 | strong |
| ≥ 24 | very-strong |

词组配方按词数查表（5 词起算 strong）。评分不进日志、不进 `--json`，仅人类通道。

### 17.4 `Password` 一等分类

```rust
Category::Password => &[("password", Concealed)]   // builtin_fields
Category::Password => "password"                  // default_secret_field
```

- 唯一字段 `password`（`Concealed`），无 `url` / `username` / `expires`。它就是单值密码——不需要撑出一个分类骨架。
- `expires_at` 条目级字段仍然可用（v0.2 已在 `Entry` 上），所以「90 天后这条密码过期」语义不变。
- `ALL_CATEGORIES` 由 7 升 8；`template list` 自动多一行；`akey get --reveal --json` 路径不变。

### 17.5 审计检查项

`doctor` 增加以下探针（命名稳定，`checks[].name` 即 key）：

| name             | status | 触发 |
|---|---|---|
| `weak_secrets`   | warning / ok | 任一 secret 字段：长度 < 8 / 单一字符集 / 命中 ~1000 词常见清单（内置 ~5 KB） |
| `reused_secrets` | warning / ok | 跨条目同值（用 `field_value_hash`，已存在；不要新算） |
| `stale_rotations`| warning / ok | `apikey` / `token` 类条目 `rotated_at` 距今 > 365 d 且未被软删 |
| `expiring`       | （保留） | 已实现，30 天窗口，ok/warning |

新检查默认 `warning`（不致让 doctor 退 1）；只有现存 `error` 等级才让命令非零退出。`weak_secrets` 在所有 `Concealed` / `Notes` / `SshKey` / `Otp` 字段上跑；命中后 `detail` 只列条目名+字段 ID，绝不含值或哈希本身——`tests::audit_check_never_includes_value_or_hash` 钉住。

新增独立命令 `akey audit --json`：列出每条命中，按 `weak | reused | stale | expiring` 分组。`--json` 形状 `{ok:true, data:{weak:[{name,field,reason}], reused:[[name,other]], stale:[{name,days_since_rotation}], expiring:[{name,expires_at}]}}`。任何一处都不含值或哈希。

### 17.6 恢复密码 UX

- `recovery set` / `init --recovery` 接受 `--min-passphrase-len <n>`（默认 12，env `AKEY_RECOVERY_MIN_LEN` 可覆盖）。低于阈值退出 2（**用法错误**，不与「错误密码」混淆——后者退出 4）。
- `recovery status` 新命令。`{configured: bool, min_length: u16, current_length: u16 | null, strength: "too-short"|"weak"|"fair"|"strong"|"very-strong"}`。**不含密码本身**——`tests::recovery_status_envelope_carries_no_passphrase` 钉住。
- `recovery rotate` 在 `--min-passphrase-len` 上与 `set` 同源；用旧密码解 `recovery.age`、用新密码重写。
- 长度阈值上界 1024；下限默认 12，最小允许 8（再低则不是「密码恢复」而是「密码提示」，设计不鼓励）。

### 17.7 `vault.age` 格式：`v1` → `v2`

- `version` 字段从 `1` 升 `2`。
- v1 → v2 迁移：`version := 2`，条目 / 令牌 / 墓碑集**原样保留**。无 `Category::Password` 条目的 v1 vault 直接升 v2 不丢信息。
- `merge3` 在 `(v1, v2, v1)` 或 `(v1, v2, v2)` 的合并中，输出 `version = max(ours.version, theirs.version)`，条目集合照旧按 ID 并——空集的一方不会触发迁移错误。
- `store::load` 在读到 `version: 1` 时调用 `migrate::v1_to_v2` 一次并原地落盘（同步仍由下次 `sync` 触发；这里只**就地**写，不主动 push）。
- `tests::migration_v1_to_v2_is_identity_on_entries_tokens` 与 `tests::migration_v1_to_v2_bumps_version` 在 `vault::migrate` 模块内。

### 17.8 实现顺序

1. `vault::generator`（含词表 `include_str!`）+ 词组采样 + 池函数。
2. `vault::migrate::v1_to_v2` + `store::load` 接入；`merge3` 版本取最大。
3. `Category::Password` 与 `ALL_CATEGORIES`、模板渲染。
4. `cmd::audit` 与 `admin::doctor` 接入四个新探针。
5. `cmd::Generate` + `RecoveryCommand::Status` + `cli.rs` 接线；`schema --json` 自动反映。
6. 双语字符串（每条新的人类可读消息都进 `i18n::m(...)`）。
7. `cargo test` 全过；`cargo clippy -- -D warnings`；`tests/contract.rs` 钉 JSON 信封。

---

## 18. `gpuix` 桌面 GUI（`akey-gui`）

面向人的桌面界面。技术栈是 **GPUI（Zed 的 GPU 加速 UI 框架，crate `gpui`）**。本节只定义架构与边界；视图清单见 `gui/src/views/`。

### 18.1 为什么是 workspace member，不是 feature

`gpui` 依赖 `wgpu` / Metal / Vulkan / blade 这一整条 GPU 栈。把它做成 CLI crate 的可选 feature 会让两件事同时发生：`cargo build` 的 manifest 里出现 GPU 依赖（审计面扩大），以及 `cargo vendor` / `cargo audit` 的输出被污染。所以：

```toml
# 根 Cargo.toml
[workspace]
members = ["gui"]
```

- `cargo build`（根目录）→ 只构建 `akey` CLI，依赖图**逐字节不变**。
- `cargo build -p akey-gui --features gpui` → 构建 GUI。
- `gui` **不**把 `akey` 当依赖；它通过子进程调用 `akey`。

### 18.2 GUI 的 API 就是 CLI 的 `--json`（子进程，不链接库）

`Output` 直接写 `std::io::stdout()`，没有可注入的 sink。因此「在进程内复用 `cmd::*`」只有两条路，都不该走：

- 给 `Output` 加 sink → 改动 CLI 的输出纪律核心，`contract::*` 一整套测试都在钉它；
- 在 GUI 里另写一套 reveal / write 闸门 → **违反 FR-4 的三重门必须唯一**。

于是 GUI 与 CLI 的边界是**进程**：

```
akey-gui ──(std::process::Command)──> akey --json <verb>
                                      ↑ 闸门在此运行
```

这条边界有三个好处：

1. **闸门无法被绕过**：`reveal` 走的还是 `get --reveal`，`AKEY_NO_REVEAL` / 令牌 `--deny-reveal` / 条目 `reveal=deny` 照常生效，退出 7。
2. **契约已被测试钉死**：`--json` 信封是 FR-3 的对外契约，`tests/contract.rs` 在回归它。
3. **CLI 依赖图零改动**。

代价是每次操作一次进程创建（macOS 上 ~3–5 ms）——对交互式 GUI 无感。

**二进制定位**（顺序）：`$AKEY_GUI_BIN` → `PATH` 上的 `akey` → 报错并给出安装提示。绝不静默退回内置实现。

### 18.3 启动闸门

`main` 在开窗前跑一次 `akey whoami --json`：

| 结果 | 行为 |
|---|---|
| `ok` | 进入主界面 |
| 退出 4（`locked`，无 config） | 显示「本机尚未初始化，请运行 `akey init`」，**不**提供替代初始化向导——初始化要选远端与恢复密码，属于 CLI 的显式动作 |
| 二进制找不到 | 显示 `$AKEY_GUI_BIN` 提示 |

`doctor --json` 的 `data.checks[]` 里任何 `status: "error"` 会在标题栏挂一个告警点；不阻断（否则设备被吊销时会连只读界面都打不开）。

### 18.4 明文生命周期（FR-31）

GUI **不持久化任何明文**：

- reveal 的结果是一个 `Revealed` 值，只在内存里，同时绑定条目 `id` 与字段 `id`；普通
  `EntryDetail` 始终保持遮蔽，揭示响应不得替换它；任一时刻最多保留一个字段的明文；
- 触发丢弃：切换到别的条目、窗口失焦、真正唤醒 UI 的 30 秒定时器、或显式「隐藏」；
- `Revealed` 不实现 `Debug`（同 `Field` / `Entry` 的理由）；不写 config、不写日志、不进 panic message；
- 剪贴板写入是**显式动作**（一个按钮），且提示「剪贴板可能被其它程序读取」。

### 18.5 六块界面（对应 README 路线图）

| 界面 | 底层调用 |
|---|---|
| 列表 | `akey list --json`（含 `--tags` / `--category` / `--expiring` 过滤） |
| 详情 + 揭示 | `akey get <item> --json`，reveal 时追加 `--reveal` |
| 新增 / 编辑 | `akey set <item> --category <c> --stdin`（秘密走子进程 stdin，**永不** argv）；`akey edit` 改元数据 |
| 同步 | `akey sync --json`；退出 5 → 切到冲突面板（`conflicts --json` + `resolve --ours\|--theirs`） |
| 设备与令牌 | `akey devices list/trust/untrust/rm`、`akey token create/list/rm` |
| 恢复密码 | `akey recovery set/rotate/unlock/status` |

### 18.6 目录

```
gui/
  Cargo.toml            akey-gui；gpui 是 optional，feature = "gpui"
  src/
    main.rs             feature 门：有 gpui 就开窗，没有就说明原因后退出 2
    lib.rs              导出 backend / model
    backend.rs          定位二进制、执行、解析信封（**纯逻辑，可测**）
    model.rs            从 `--json` 载荷反序列化的视图结构（**纯逻辑，可测**）
    app.rs              Application::new().run（feature = "gpui"）
    views/
      list.rs           列表 + 过滤
      detail.rs         详情 + reveal
      edit.rs           新增 / 编辑表单
      sync.rs           同步 + 冲突
      devices.rs        设备 + 令牌
      recovery.rs       恢复密码
```

`backend.rs` 与 `model.rs` 不依赖 `gpui`，因此 `cargo test -p akey-gui`（默认 features）在**没有 Metal 工具链**的机器上也能跑——GUI 的可测部分与渲染部分是分开编译的。

### 18.7 深浅主题与国际化

品牌文档已经定义了两套表面，所以主题不是发明出来的，是**读出来的**：

| | ground | ink |
|---|---|---|
| dark | `#0B1220`（navy） | `#F8FAFC`（light） |
| light | `#F8FAFC` | `#0B1220` |

`#2563EB`（letterform）与 `#06B6D4`（connections）是中调，两套里都保持原位。severity 色（danger/warn/ok）品牌未定义，是唯一的外来色，且已标注。

`theme.rs` **不依赖 `gpui`**：颜色以 `u32` 打包 hex 保存——这正是品牌规范书写它的单位，可直接比较、可精确断言，且无需 GPU 工具链即可测试。视图通过 `views::K` 这一个转换点转成 `Rgba`。

**可读性是属性，不是口味**：测试断言正文在两种外观下都满足 WCAG AA（≥4.5:1），次级文字 ≥3:1，severity 色 ≥3:1，并且半透明 token 会**先与 ground 合成再断言**——未合成的对比度没有意义。这条测试抓到过一个真实缺陷：浅色主题下 `#F8FAFC` 文字压 `#06B6D4` 只有 2.32:1，已改为两种外观都用 navy 压 cyan。

`i18n.rs` 复制 CLI 的设计：消息是**值**（`Msg { en, zh_cn }`）而不是 key，因此不存在「缺翻译」状态；`t!` 宏在编译期校验占位符数量一致。与 CLI 的唯一区别是 GUI 的语言可在运行时切换，所以 `Lang` 存在 app 上而不是进程全局。初始值沿用 CLI 的优先级（`AKEY_LANG` > `LC_ALL` > `LC_MESSAGES` > `LANG` > `en`），并同样区分「显式指定不支持的语言」与「locale 恰好不支持」——后者回退英文而不是拒绝启动。

### 18.8 品牌资产：两个必须知道的实现事实

1. **`Application::new()` 装的资产源是 `()`**，它对任何路径都返回 `None`——所以 `img("assets/brand/…")` 会**静默地什么都不画**。必须用 `Application::with_assets(...)` 装一个真正能读文件的源（`gui/src/assets.rs`）。路径按 `CARGO_MANIFEST_DIR` 解析为绝对路径，否则会随启动目录变化。这条有测试守着（断言两个 lockup 都真实存在）。
2. **lockup 的背景是烤进 PNG 的**（`#0B1220` / `#F8FAFC`），不是透明的。因此在任何「抬升过的」表面上贴 lockup 都会画出一个可见矩形。页头背景因此**必须是 ground 本身**，而不是 `surface`——这样 lockup 才严丝合缝。品牌文档 rule 2 说的「按表面选变体」正是这件事；`icon-transparent-1024.png` 才是「你自己控制表面时该用的那个」。

---

## 19. Harness 抽象层（`src/agent/`）

`akey mcp` 只提供元数据，但要让它真正被 agent 用上，必须把它注册进每个 harness 的配置，并放一份 `SKILL.md`。如果每个 agent 写一段专用逻辑，代码会变成 N 份几乎相同的安装器；如果抽成 trait，又会把「配置长什么样」这种纯数据藏进 `impl` 里。这里选的是**数据驱动**：harness 是一行数据，配置格式是一个适配器。

### 19.1 分层

| 层 | 文件 | 职责 | 不知道什么 |
|---|---|---|---|
| 注册表 | `registry.rs` | harness 的 id / 别名 / 作用域 / 配置候选路径 / 格式 / 入口语法 / skill 根 / 可选的原生 CLI | 不知道文件内容如何解析 |
| 适配器 | `config.rs` + `config/{json,toml,yaml}.rs` | 匹配与决策流水线；按格式结构化读写 JSON/JSONC/TOML/YAML | 不知道 harness 叫什么 |
| skill | `skill.rs` | 内嵌 `SKILL.md`、sidecar 记账、覆盖与卸载判定 | 不知道 MCP 配置怎么写 |
| 选择 | `selection.rs` | 默认 / 显式选择、作用域过滤 | 不知道具体文件格式 |
| 原生委派 | `native.rs` | 查找并调用 harness CLI，捕获输出并诊断失败 | 不知道配置格式 |
| 生命周期 | `install.rs` / `uninstall.rs` | 全量规划后再应用、生成安装 / 卸载报告 | 不知道某个具体 agent 的路径 |
| 只读检查 | `inspect.rs` | `list` / `status` / `print` | 不写任何文件 |
| 公共出口 | `mod.rs` | 重导出与 `display_path` | 不含生命周期逻辑 |

`Harness` 没有方法能「安装自己」。它只回答 `config_path`、`skill_dir`、`native_args` 这类纯查询；写入永远经过同一个 `config::plan` / `config::apply`，移除永远经过 `config::plan_remove` / `config::apply_remove`。因此新增一个 harness 通常只是往 `HARNESSES` 加一行；如果它有原生 CLI，再在 `native_args` 里补上该 CLI 的 `mcp add` 语法即可。`native_cli` 是 `Option`：Cursor、Kiro、Devin 没有 akey 可委托的 CLI，注册表直接写 `None`，安装器不会去找可执行文件，也不会假装存在原生路径。

`McpStyle` 以**语法**命名（`Claude` / `Codex` / `Hermes` / `OpenCode` / `Plain`），不以 agent 命名：新 harness 往往复用已有语法，而同一个 agent 也可能在不同作用域用不同文件。`Plain` 是 MCP 生态最常见的裸 stdio 形状 `{"command": "akey", "args": ["mcp"]}`，不带 `type` 判别字段；Cursor、Kiro、Devin 都用它。

### 19.2 两个可安装物

1. **MCP 注册**——让 harness 启动 `akey mcp`。这是「agent 能发现金库」的前提。
2. **`SKILL.md`**——教 agent 何时用 `akey`、如何用 `run` 交付、以及哪些动作被禁止。没有它，MCP 只告诉 agent「有什么」，不告诉它「该怎么用」。

skill 目录旁的 `.akey-managed` 记录 `tool`、`version`、`sha256`、`installed_at`。安装时：文档相同 → 内容不动（必要时补写 sidecar）；文档不同但 sidecar 匹配 → 说明是旧版本，可升级；文档被本地改过 → 冲突，必须 `--force`。这样既不覆盖用户的修改，也不把 akey 自己的旧版本当成用户修改。

卸载时镜像同一套判断：文档与 sidecar 都属于 akey → 删除两者；只剩 sidecar（用户删了文档）→ 清理 sidecar；文档存在但被改过、或没有 akey 的 sidecar → 冲突，必须 `--force`。只删 akey 的 sidecar，不碰其他工具的 sidecar。目录只有在删完后为空时才移除，用户放在里面的其他文件会让目录保留。

### 19.3 计划先于写入

`install` 与 `uninstall` 都先对**所有**选中的 harness 做完整规划，任何一个配置损坏或 skill 冲突都会在写第一个字节之前失败。之后才逐个应用。应用阶段仍可能中途失败（例如第二个 harness 的原生 CLI 退出非零），但每个写入器都是幂等的，重跑同一条命令即可收敛。这是有意的取舍：跨文件事务需要日志与回滚，而幂等重跑不需要。

### 19.4 原生 CLI 只负责「新增」

harness 自己的 CLI 最懂自己的配置，但它通常没有「替换某个条目」的语义，也不保证保留注释。规则因此是：

- `Change::Added` 且该 harness 声明了 `native_cli`、并在 `PATH` 上找到了它 → 调用它；调用后**重新读取配置**，确认条目真的可用，否则报 `harness` 错误并提示 `--no-native`。
- `Change::Replaced`（`--force`）→ 永远走结构化编辑。原生 CLI 可能追加第二个同名条目，而不是替换。
- `native_cli` 为 `None`、原生 CLI 不存在，或传了 `--no-native` → 结构化编辑。
- 原生 CLI 存在但执行失败 → 直接报 `harness` 错误，**不自动回退**。CLI 可能已经写了一半配置；此时再盲目改文件会把两份修改叠在一起。错误信息给出 `--no-native`，由人决定是清理还是重试。

子进程的 stdout/stderr 一律捕获，stdin 设为 null：harness CLI 的输出不能污染 `akey --json` 的 stdout。

### 19.5 匹配只比较自己拥有的键

`akey` 条目的 `env`、以及用户添加的任意额外键，都不参与匹配——它们不影响 `akey mcp` 的行为，也不该让「已经装好了」变成冲突。比较的是：

- `command` + `args` 必须等价于 `akey mcp`；
- `type`（若存在）必须是该 harness 认识的 stdio 变体；`Plain` 接受缺省 `type`，也接受显式 `stdio`，但其他传输类型算冲突；
- Hermes / OpenCode 的 `enabled: false` 视为冲突，因为条目存在但不会运行（Claude Code 与 Codex 没有这个字段）；
- Cursor / Kiro / Devin 的 `disabled: true` 同样视为冲突，`--force` 会把它替换成可运行的条目。

`--force` 只替换这些拥有的键，保留 `env` 与其他键。JSON 用 `jsonc-parser` 做 CST 编辑，因此注释和尾随逗号不会丢；TOML 用 `toml_edit`，YAML 用 `yaml-edit`，理由相同。

### 19.6 作用域与选择

`user` 写用户主目录，`project` 写当前工作目录（可提交进仓库）。Codex 与 Hermes 只有 user；Claude Code、Cursor、OpenCode、Kiro、Devin 两者都有。Kiro 的 workspace 配置会覆盖 user 配置，Devin 的 `.devin/mcp_config.local.json` 则不在 akey 的管理范围内。

`AKEY_AGENT_HOME` 可覆盖主目录，`HOME` / `USERPROFILE` 是默认值。它**不是** `AKEY_HOME`：后者是 akey 自己的私有目录（`~/.config/akey`），而 harness 配置在真实主目录里。

`selection.rs` 把选择规则限定为「默认」与「显式」两种：

- `status` / `print` 不点名 → 选中所有支持该作用域的 harness，静默跳过不支持的。
- 点名了 `codex --scope project` → 报错。用户既然打了名字，就需要知道 Codex 没有 project 作用域，而不是安静地什么都不做。
- `install` / `uninstall` 必须点名或传 `--all`。不点名就改动机器上所有 harness，是过于意外的副作用。

### 19.7 卸载与共享 skill

`uninstall.rs` 的语义是「移除 akey 写进去的东西」，不是「恢复安装前的备份」：

- 配置里没有 `akey` 条目 → no-op；有且匹配 → 删除该条目；有但内容不同 → 冲突，`--force` 才删。
- 配置文件本身**永不删除**，只编辑其中的 `akey` 键；清空后的容器（如空的 `mcpServers`）可以留在原处。
- `SkillState::Modified` / `Unmanaged` 需要 `--force`。缺失的 sidecar 会被顺带清理，避免留下孤儿记录。
- 共享 skill 只删一次，报告按真实文件去重（Codex + OpenCode 共用 `~/.agents/skills/akey`）；但每个 harness 行会带 `shared_with`，UI 提示删除会影响另一个 harness。删除后用 `akey agent install <harness> --only skill` 可以只把文档装回来。

### 19.8 新增一个 harness

1. 在 `registry.rs` 的 `HARNESSES` 加一行：id、别名、作用域、配置候选、格式、语法、入口 key、skill 根、`native_cli`、文档链接；有原生 CLI 时再在 `native_args` 补一条 `mcp add` 语法，没有就写 `None`，安装会直接走结构化编辑。
2. 配置格式是新的 → 在 `ConfigFormat` 加变体，在 `config/` 下新增适配模块，并在 `config.rs` 的 inspect / draft / remove 分发点接入。
3. 入口语法是新的 → 在 `McpStyle` 加变体，并补齐 `EntryView::problems` 与各格式的写入形状。
4. 在 `docs/AGENT-INTEGRATION.md` §6.1 的差异列表补一条，并加一个使用临时 home 的测试。

不需要改 `cmd/agent.rs`、`mod.rs` 或报告层：报告类型与对应生命周期同文件，并按注册表生成。

### 19.9 非目标

- **不安装 akey 本身**。二进制从哪来是安装脚本的事。
- **不管理凭据**。这一层只写配置与文档。
- **不读取值**。安装器从不打开金库。
- **不常驻**。没有 daemon、没有 watcher；`status` 是只读的一次性检查。

