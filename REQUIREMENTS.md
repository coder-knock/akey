# akey — 需求文档 v0.2

> **English abstract.** Requirements and external contracts for `akey`, an encrypted credential
> vault that AI agents drive from the command line. §5 compares the feature surface against the
> 1Password CLI item by item (§5.1 adopted · §5.2 adopted with changes · §5.3 rejected); §6 lists
> functional requirements, §7 non-functional, §8 the threat model and key hierarchy, §9 the data
> model, §10 the sync design, §11 the merge rule table, §12 the CLI contract for agents.
> The body is written in Chinese; `README.md`, `docs/AGENT-INTEGRATION.md` and `SKILL.md` are bilingual.

> v0.2 变更：对标 1Password CLI 重排功能面（§5）；D1–D5 已拍板（§0）。
> 开发顺序由你指定：**文档 → 测试 → 实现**。本文是第一步的产出。
> `akey` 为占位名，可改。

---

## 0. 已定决策

| | 决策 | 结论 |
|---|---|---|
| D1 | AI 明文暴露 | **默认不暴露，走注入**：AI 只知名字；`akey run` 把值注入子进程环境；明文不经 stdout、不进 LLM 上下文。按条目 `reveal` 开关 + 显式 `--reveal` 作为逃生口 |
| D2 | 本机解锁 | **每设备 X25519 密钥对 + 一次性恢复密码**：日常操作零密码、微秒级；换机用恢复密码引导 |
| D3 | 同步冲突 | **按条目自动三方合并**：不同条目改了自动合；同一条目改了保留双方并标记；绝不静默丢数据 |
| D4 | 使用范围 | **单人多设备**：一个 vault，本期不做权限模型 |
| D5 | 交付范围 | **先 CLI 跑通**（含 AI 契约、加密、git 同步、e2e 测试、AGENTS.md）；gpuix GUI 下一轮 |

---

## 1. 一句话

`akey` 是一个**加密凭证库**：Rust 单二进制 CLI 给 AI agent 用，密文通过一个 git 远程仓库在多台设备间同步；`gpuix` 桌面 GUI（下一轮）给人用。

## 2. 要解决的问题

| | 痛点 | akey 的答案 |
|---|---|---|
| P1 | AI 要用第三方 API，key 被贴进 prompt / 项目 `.env` | key 不进上下文；`akey run` 按需注入子进程 |
| P2 | 同一批 key 在多机多项目重复维护，轮换要一台台改 | 一处改，`sync` 同步到所有设备 |
| P3 | 没有"有哪些 key / 何时过期 / 谁在用"的统一视图 | `akey list` + 过期预警 + 审计日志 |
| P4 | 明文散在 `.env`/`.zshrc`，无加密、无备份、无吊销 | 静态加密 + git 版本历史 + 设备吊销 |

## 3. 角色

- **A：AI agent（主用户）** — 非交互、可并发、只应知道"用哪个名字"，不应知道明文。
- **B：人类（维护者）** — 录入 / 轮换 / 吊销 / 审计；CLI 或 GUI。

## 4. 场景

| | 场景 | 路径 |
|---|---|---|
| S1 | AI 调外部 API | `akey run --with openai -- curl -H "Authorization: Bearer $OPENAI_API_KEY" …` |
| S2 | AI 发现可用凭证 | `akey list --json` — 只出元数据 |
| S3 | AI 驱动的 MCP server | mcp.json 里 `"command":"akey","args":["run","--","npx","-y","some-mcp"]` — **配置里没有任何明文** |
| S4 | 换新机器 | `akey init --from <repo-url>` + 恢复密码 → 全部可用 |
| S5 | 轮换 | 改值 → `sync`；其他设备 `sync` 拉到 |
| S6 | 笔记本丢失 | `akey devices rm macbook` → 重新加密排除该设备 → push |
| S7 | 过期预警 | `akey list --expiring 30d` |
| S8 | 审计 | `akey log` — 哪台设备、何时、读写哪个条目（不含明文） |
| S9 | 给 CI/一次性 agent 降权 | `akey token create --allow openai,tavily --ttl 30d` |
| S10 | 配置文件模板 | `akey inject -i config.yml.tpl -o config.yml` |

---

## 5. 对标 1Password CLI

参考 `op` 的功能面，逐条决定采纳与否。

### 5.1 采纳（进本期需求）

| 1Password CLI | akey 对应 | 说明 |
|---|---|---|
| secret reference `op://vault/item/[section/]field` | `akey://[vault/]item/[section/]field` | 引用而非明文；见 §12.3 |
| `?attribute=otp\|value\|title\|type\|id` | 同 | 元数据查询（无 `purpose`：我们没有该概念） |
| `?ssh-format=openssh` | 本期未实现 | 传入按未知参数拒绝；需要时再补 |
| `op read` | `akey read <ref>` | 解析引用到 stdout/文件；受 reveal 策略约束 |
| `op run --env-file F -- cmd` | `akey run [--env-file F] -- cmd` | 环境变量注入 |
| `op run` 默认遮蔽子进程输出中的密钥 | 同 | **默认遮蔽**，`--no-masking` 关闭 |
| 变量优先级：Environment > env-file > shell | `--bundle` > `--env-file`（后者优先）> shell | 保持同样的确定性 |
| `op inject -i/-o` | `akey inject [-i F] [-o F]` | 模板渲染 |
| `op item get --format json --fields` | `akey get <item> --json --fields` | 每个 field 带 `reference` 字段 |
| `op item get` 默认隐藏 CONCEALED 字段 | `akey get` 默认隐藏，`--reveal` 显式展开 | 与 D1 完全一致 |
| `item create/edit` 赋值语句 `[<sec>.]<field>[[<type>]]=<v>` | 同 | 并警告 argv 可见，引导用 stdin/`--template` |
| `--template` / stdin 建改条目 | 同 | 敏感值的安全通道 |
| `--dry-run` | 同 | AI 友好：先预览不落盘 |
| 条目分类（Login / API Credential / …） | `--category apikey\|login\|token\|database\|ssh-key\|secure-note\|env-bundle` | 见 §9.2 |
| `item template list/get` | `akey template list/get` | 模板驱动创建 |
| 稳定 ID（26 位）与"名字或 ID"寻址 | 26 位 ID，`name` 或 `id` 皆可 | 改名不断引用 |
| `item delete --archive`（软删） | `akey rm`（默认软删）/ `--purge` | 默认软删（git 历史也留着）；`--purge` 写墓碑防对端复活 |
| `--vault` 选择容器 | ref 保留 vault 段，本期恒为 `default` | 为 D4 未来扩展留钩子 |
| favorite / tags / `list --tags` | 同 | |
| `op whoami` | `akey whoami` | 设备身份 + 仓库 + 策略 |
| `op completion bash\|zsh\|fish` | 同 + powershell | clap_complete |
| 全局 `--format json` / `--no-color` / `--debug` | 同（`--json` 为 `--format json` 别名） | |
| Events API / 审计 | `akey log` | 本地 append-only |
| `op document` | `akey doc get/put` | 任意文件附件（kubeconfig、SA json） |
| `item copy/move` | `akey cp` / `akey mv` | 单 vault 下即复制/改名 |
| `service-account create`（最小权限、可吊销） | `akey token create --allow … --ttl …` | **给 agent 的能力令牌**，见 §6 FR-15 |
| Environments MCP Server **不把密钥返回给 AI** | `akey mcp` 只暴露名字与元数据 | 见 FR-16 |
| Shell plugins（第三方 CLI 免密） | 本期不做 | 依赖常驻 GUI 授权通道；见 FR-19 |

### 5.2 改造后采纳

| 1Password | 差异 | 原因 |
|---|---|---|
| noun-verb（`op item get`） | 扁平动词（`akey get`） | AI 首用；更短、更少歧义；`item`/`vault` 这类容器本期只有一层 |
| `signin/signout/session` | 无会话，本机身份文件替代 | 无服务端 |
| `account list/add`（多账户） | `akey devices` + `--home` | 多人多账户不在本期 |
| `--session token` | `AKEY_TOKEN`（能力令牌） | 见 FR-15 |
| `--cache`（常驻 daemon） | 无 daemon；热路径本身是微秒级 | 少一个常驻进程 = 少一类故障 |
| `--encoding shift_jis/gbk` | 不采纳（仅 UTF-8） | Windows 不在本期 |

### 5.3 不采纳

`connect`（自建服务端）· `group` / `user` / `vault user`（团队权限）· `item share`（分享链接）· `update`（自更新）· passkeys · Agentic Autofill（浏览器）· `--ssh-generate-key`（不做密钥生成，只做托管）

---

## 6. 功能需求

**FR-1 凭证条目**：`id`(26 位 ULID，稳定) · `name`(唯一，`^[a-z0-9][a-z0-9._-]*$`) · `category` · `title` · `fields[]`（每个含 `label`/`type`/`concealed`/`value`/`section`）· `tags[]` · `favorite` · `url` · `notes` · `expires_at` · `reveal`(allow|deny) · `created_at`/`updated_at`/`rotated_at`/`last_used_at`/`deleted_at`

**FR-2 命令面**：`init` · `read` · `run` · `inject` · `get` · `set` · `edit` · `rm` · `restore` · `cp` · `mv` · `list` · `template` · `doc` · `token` · `devices` · `recovery` · `sync` · `conflicts` · `resolve` · `log` · `whoami` · `doctor` · `schema` · `completion` · `export` / `import` · `mcp`

**FR-3 机器可读契约（MUST）**
- 全局 `--json`（= `--format json`），统一信封 `{"ok":true,"data":…}` / `{"ok":false,"error":{code,message,hint}}`
- 退出码：`0` ok · `2` 用法 · `3` 未找到 · `4` 未解锁/鉴权失败 · `5` 冲突 · `6` 同步失败 · `7` 策略拒绝 · `8` 令牌越权
- **stdout 只放数据；诊断一律 stderr**
- **绝不弹交互 prompt**；密钥经 stdin（`set --stdin`）或 `--template` 传入；明文出现在 argv 即打印警告并提示改用 stdin
- 幂等：`set`/`sync`/`init --from`/`token create --name` 重复执行安全
- `--dry-run` 支持所有写命令

**FR-4 明文暴露控制（MUST，D1）**
- `akey get` / `read` 默认隐藏 `concealed` 字段值，输出 `••••••••`（附 `reference`，方便下游引用而不是取值）
- `--reveal` 才出明文，且需同时满足：条目 `reveal=allow`、当前令牌未被禁用 reveal、非 `AKEY_NO_REVEAL=1`
- `run` / `inject` 不受限（它们不把明文交给调用者）
- 策略拒绝时退出码 `7`

**FR-5 引用解析（MUST）** — `akey://…` 全语法见 §12.3
**FR-6 注入运行（MUST）** — env 变量与 `--env-file` 中的引用被解析为明文注入子进程；**子进程 stdout/stderr 中出现的密钥默认遮蔽**，`--no-masking` 关闭；退出码透传子进程
**FR-7 模板渲染（MUST）** — `inject`，stdin→stdout，`-i`/`-o`
**FR-8 跨设备同步（MUST）** — 见 §11
**FR-9 冲突处理（MUST，D3）** — `conflicts` 列出、`resolve --ours|--theirs` 收敛。
`sync` 一旦产生冲突副本，即返回退出码 `5` 且 stdout 为空（提交与推送本身已完成）；
详情由 `akey conflicts --json` 给出。
**FR-10 设备管理（MUST）** — `devices list|add|rm|rename`；`rm` 重新加密并排除该设备
**FR-11 恢复（MUST，D2）** — `recovery set|rotate|unlock`；`init --from` 走恢复密码引导
**FR-12 审计日志（MUST）** — 本地 append-only，记 `设备ID / 条目ID / 动作 / 结果 / 时间戳`；**不含明文**
**FR-13 过期与健康（SHOULD）** — `list --expiring 30d`；`doctor` 检查权限位、远端可达、冲突、令牌过期、身份是否仍被授权
**FR-14 导入导出（SHOULD）** — `json` / `dotenv` / `1password csv`；导出即明文，需 `--yes` 且写明目标
**FR-15 能力令牌（MUST，对标 service account）**
- `akey token create --name <n> [--allow <item,…>] [--deny-reveal] [--ttl 30d]` → **只回显一次**
- 用途：`AKEY_TOKEN=<t> akey run --with openai -- …`；或给 CI / 临时 agent
- 校验：令牌哈希（SHA-256）存于 vault；每次使用校验 `allow` 列表与 `ttl`
- **令牌是只读凭据**：任何写命令（`set/edit/rm/restore/cp/mv/resolve/import/doc put`）
  在有令牌时一律拒绝（退出码 `7`）。否则一个只被授权读单条目的 agent 就能改库或删条目，
  作用域形同虚设
- **作用域对注入同样生效**：`run` / `inject` 不经过 reveal 闸门，但必须逐条校验引用所属条目，
  否则 `--allow` 会被 `run --with X=akey://secret/credential -- sh -c 'echo $X'` 绕过
- `export` 在有令牌时只导出作用域内的条目
- 越权退出码 `8`；`token list` / `token rm` 吊销
**FR-16 MCP server（MUST）** — `akey mcp` stdio；**只暴露条目名与元数据，永不返回值**；写操作为可选工具
**FR-17 Agent 自带说明书（MUST）** — `AGENTS.md` 随仓库与二进制分发
**FR-18 补全（SHOULD）** — `completion bash|zsh|fish|powershell`
**FR-19 Shell plugin（本期不做）** — 1Password 的 shell plugin 是"用生物识别给第三方 CLI 免密注入"。
它依赖一个常驻的 GUI 授权通道，而本期的定位是无守护进程的单二进制；等 GUI 轮次再评估。
**FR-20 文件附件（SHOULD）** — `doc get/put`，用于 kubeconfig、service-account json

---

## 7. 非功能需求

| | 要求 |
|---|---|
| NFR-1 | 安全模型见 §8 |
| NFR-2 | 性能：除引导 / 改恢复密码外，任意命令 **p95 < 100ms**（热路径无 KDF、无网络） |
| NFR-3 | 依赖：CLI 为**单二进制**；不依赖 OpenSSL；运行期唯一外部程序是 `git` |
| NFR-4 | 平台：macOS arm64 首发 → Linux；**Windows 本期不做** |
| NFR-5 | 原子性：写 `tmp + fsync + rename`；并发由文件锁串行化 |
| NFR-6 | 可测：同步/冲突/吊销须有端到端测试（两个临时 repo 模拟两台机器） |
| NFR-7 | 零遥测、零回连 |
| NFR-8 | 离线可用：除 `sync` 外所有命令不需要网络 |
| NFR-9 | 合规：任何日志/错误信息不得包含明文字段值 |

## 8. 安全模型

| 威胁 | 对策 |
|---|---|
| T1 远端仓库泄露 | 仓内只有密文；无私钥/恢复密码不可解 |
| T2 明文进 LLM 上下文 / 终端 scrollback / 日志 | D1 + FR-4 + FR-6 遮蔽 + NFR-9 |
| T3 本机被读 | 身份文件 `0600`；vault 密文；无明文落盘 |
| T4 设备丢失 | `devices rm` + 重新加密 |
| T5 恢复密码泄露 | 只解出**引导身份**；可 `recovery rotate` 并 `devices rm` 旧设备 |
| T6 令牌泄露 | 作用域 `--allow` + `--ttl` + 可吊销 + `--deny-reveal` |
| T7 供应链 | 最小依赖 + `cargo audit` |

**密钥层次**

```
每设备   age X25519 密钥对    ~/.config/akey/identity.key   (0600, 永不进 git)
仓库     recipients.json      所有设备 + 引导身份的公钥（公开）
仓库     vault.age            age 多收件人加密（所有设备 + 引导身份）
仓库     recovery.age         age passphrase(scrypt) 加密的"引导身份私钥"
```

热路径只有 X25519 + ChaCha20-Poly1305（微秒级）；scrypt 仅在 `init` / `init --from` / `recovery rotate` 跑。

## 9. 数据模型

### 9.1 条目

```jsonc
{ "version": 1,
  "vault": "default",
  "entries": {
    "<id>": {
      "id": "01J…", "name": "openai", "category": "apikey", "title": "OpenAI",
      "fields": [
        { "id":"credential", "label":"credential", "type":"concealed",
          "value":"sk-…", "reference":"akey://default/openai/credential" },
        { "id":"org", "label":"org", "type":"string", "value":"org-xxx",
          "reference":"akey://default/openai/org" }
      ],
      "tags": ["llm","prod"], "favorite": false, "url": "https://platform.openai.com",
      "notes": "…", "expires_at": "2027-01-01T00:00:00Z",
      "reveal": "allow",
      "created_at":"…","updated_at":"…","rotated_at":"…","last_used_at":"…","deleted_at": null
    }
  },
  "tokens": { "<id>": { "name":"ci", "hash":"base64(sha256(token))", "allow":["openai"],
                        "deny_reveal":true, "expires_at":"…", "created_at":"…" } } }
```

**`reference` 不在密文里**：上例中字段的 `reference` 是命令输出（`get` / `list` / MCP）
**现算**出来的——它由条目名与字段 slug 推导，不需要存储。密文里只留字段本身，
这样改名后引用自动跟着变，也不会因为多存一份而出现两处不一致。

### 9.2 分类与内置字段

| category | 内置字段 |
|---|---|
| `apikey` | `credential`(concealed) · `username` · `url` · `expires` · `notes` |
| `login` | `username` · `password`(concealed) · `url` · `one-time password`(otp) |
| `token` | `token`(concealed) · `scopes` · `expires` |
| `database` | `host` · `port` · `database` · `username` · `password`(concealed) |
| `ssh-key` | `private key`(concealed) · `public key` · `fingerprint` |
| `secure-note` | `notes`(concealed) |
| `env-bundle` | 任意多字段，用于批量注入 |

## 10. 目录布局

```
<repo>/                     ← git 同步的就是这个目录
  vault.age                 密文库（单文件快照）
  recovery.age              引导身份（未设恢复密码时不存在）
  recipients.json           设备与引导身份公钥（公开）
  AGENTS.md                 agent 说明书
  .gitignore

~/.config/akey/             ← 本机私有，永不同步
  config.toml               仓库路径、远端、本机设备名（0600）
  identity.key              AGE-SECRET-KEY-1…（0600）
  audit.log                 审计
  vault.lock                文件锁
```

## 11. 同步设计

选**单文件密文快照 + 解密后三方合并**（而非"一条目一文件"）：快照语义一致、仓库对象少、冲突报告可读。

```
akey sync
  1. 加锁
  2. git fetch
  3. HEAD == 远端            → 无事可做
     HEAD 是远端的祖先        → 快进（纯拉取）
     远端是 HEAD 的祖先        → push
     分叉                     → 三方合并：
        base   = decrypt(git show <merge-base>:vault.age)
        ours   = decrypt(工作区 vault.age)
        theirs = decrypt(远端 vault.age)
        merged = merge3(base, ours, theirs)      # 规则见 §11.1
        写入 → commit → push（非快进则有限次重试）
  4. 解锁
```

### 11.1 三方合并规则（按条目 ID）

| base | ours | theirs | 结果 |
|---|---|---|---|
| = | = | ≠ | 取 theirs |
| = | ≠ | = | 取 ours |
| ≠ | = | = | 取 ours（二者相同） |
| = | ≠ | ≠ 且 ours == theirs | 取 ours |
| = | ≠ | ≠ 且不同 | **冲突**：ours 保留原名；theirs 落为 `<name>.conflict.<短ID>`，打 `conflict` 标签并记录对端设备与时间 |
| 有 | 已软删 | 已改 | 保留改动版 + 标记冲突（不静默删除） |
| 有 | 已软删 | 未改 | 删除生效 |

合并结果按 ID 排序、`updated_at` 取新，保证**同输入必得同输出**（幂等、可测）。

## 12. CLI 契约（AI 面向）

### 12.1 全局标志

`--json` · `--format human|json` · `--no-color` · `--quiet` · `--debug` · `--home <dir>` · `--repo <path>` · `--token <t>`（或 `AKEY_TOKEN`）· `--yes` · `--dry-run`

环境变量：`AKEY_HOME` · `AKEY_TOKEN` · `AKEY_NO_REVEAL` · `AKEY_DEVICE_NAME`

### 12.2 输出信封

```json
{"ok": true,  "data": { … }}
{"ok": false, "error": {"code":"not_found","message":"entry 'foo' not found","hint":"run `akey list`"}}
```

### 12.3 引用语法

```
akey://[<vault>/]<item>[/<section>]/<field>[?<query>]
query := attribute=value|otp|title|type|id
```
- 大小写不敏感；每段允许字母数字与 `-` `_` `.`（**不允许空格**：否则 env 文件与模板里的无引号扫描会与语法冲突）
- `$VAR` 在引用中展开（如 `akey://$APP_ENV/db/password`），展开源 = 当前 env
- `item` 可用名字或 ID

### 12.4 典型调用

```bash
akey run --with openai -- curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
echo 'DB_PASSWORD=akey://db/password' > .env && akey run --env-file .env -- ./app
akey get openai --json | jq -r '.data.fields[] | select(.concealed) | .reference'
akey inject -i config.yml.tpl -o config.yml
akey set github --category login --title GitHub username=me password-stdin
akey list --tags llm --json
akey sync --json
akey token create --name ci --allow openai,tavily --deny-reveal --ttl 30d
```

## 13. 分期

| 期 | 内容 |
|---|---|
| **本期** | 上述 CLI 全部 MUST + 主要 SHOULD；gpuix GUI 不做 |
| 下一轮 | gpuix 桌面 GUI（列表 / 增改 / 揭示 / 同步 / 设备与令牌管理 / 恢复密码） |
| 以后 | 多 vault / 项目分组（D4-②） · Linux 打包 · shell plugin 目录 |

## 14. 不做（本期）

团队权限 · Windows · 自建服务端 · 浏览器插件 · 自动轮换对接第三方 · OAuth 授权码流程 · passkey · 分享链接 ·
`akey env`（把明文导出成 shell 环境变量——正是 D1 要避免的形态，用 `run`/`inject` 覆盖）·
shell plugin（见 FR-19）· `?ssh-format=openssh`（见 §5.1）

## 15. 需要你提供

1. **git 远端**：自建 GitHub 私库 / Gitee / 腾讯 / 其他（本机已装 `gh 2.101.0` 与 SSH key `github.pub`/`gitee.ssh.pub`/`tencent-ly.pub`，可代建）
2. **仓库名与可见性**（建议 private）
3. 二进制名 `akey` 是否接受

## 16. 本机环境实测

```
cargo 1.97.1 · rustc 1.97.1 · git 2.54.0 (Apple Git) · gh 2.101.0
node v26.5.1 · bun 未安装（下一轮 GUI 需要）
macOS darwin 27.2.0 · Apple M2 Max · crates.io 与 npmjs 可达 · gpg(brew) 已装
```
