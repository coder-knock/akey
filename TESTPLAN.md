# akey — 测试计划

> **English abstract.** The test plan for `akey`: a requirement-by-requirement matrix naming what
> each test proves and at which layer (`U` unit · `C` CLI contract · `E` end-to-end), the
> multi-device fixtures, the four global invariants every contract test asserts, and an explicit
> list of what is deliberately *not* tested. The body is written in Chinese.

> 依据 `DESIGN.md`。**测试先于实现**：下表是写代码前的验收依据。
> 分层：`U` 单元（纯函数）· `C` 契约（CLI 外部可观测行为）· `E` 端到端（多进程/多仓库）。
> 每条测试必须能**因一个真实 bug 而失败**；不写只断言实现细节的测试。

---

## 1. 覆盖矩阵

| 需求 | 测试 | 层 | 断言什么 |
|---|---|---|---|
| FR-1 条目模型 | `model::name_validation` | U | 合法名通过；大写/空格/前导 `-` 拒绝 |
| FR-1 | `model::field_concealed` | U | `Concealed/Notes/SshKey` → true，其余 false |
| FR-3 信封 | `contract::success_envelope` | C | stdout 是 `{"ok":true,"data":…}` 合法 JSON |
| FR-3 | `contract::error_envelope` | C | 失败时 stdout 为空、stderr 有诊断、退出码正确 |
| FR-3 | `contract::stdout_stderr_separation` | C | 诊断绝不污染 stdout（用管道分别抓取） |
| FR-3 | `contract::exit_codes` | C | 12 个错误场景各自映射到 2/3/4/5/6/7/8/1 |
| FR-3 | `contract::no_prompt_non_tty` | C | 非 TTY 下任何命令不阻塞等待输入（超时即失败） |
| FR-3 | `contract::idempotent_set` | C | 同 `set` 连跑两次，vault 字节稳定（除时间戳） |
| FR-4 暴露控制 | `contract::get_conceals_by_default` | C | `get` 输出含 `••••`，且**不含**明文串 |
| FR-4 | `contract::get_reveal_requires_policy` | C | `reveal=deny` 时 `--reveal` 退出 7 |
| FR-4 | `contract::no_reveal_env` | C | `AKEY_NO_REVEAL=1` 下 `--reveal` 退出 7 |
| FR-4 | `contract::get_exposes_reference` | C | 隐藏值的同时给出 `reference` 串 |
| FR-5 引用 | `reference::parse_table` | U | 表驱动：合法/非法、可选 vault、section、query |
| FR-5 | `reference::var_interpolation` | U | `$APP_ENV` 展开；未定义变量 → usage |
| FR-5 | `reference::resolve_by_id_and_name` | U | 名字与 ID 都能命中；均不存在 → not_found |
| FR-5 | `reference::ambiguous_section` | U | 同名跨 section → ambiguous |
| FR-6 注入 | `inject::env_injection` | C | 子进程读到明文；调用者 stdout 无明文 |
| FR-6 | `inject::env_file` | C | `--env-file` 中的引用被解析 |
| FR-6 | `inject::precedence` | C | env-file 覆盖 shell 环境变量 |
| FR-6 | `inject::exit_code_passthrough` | C | 子进程退 42 → akey 退 42 |
| FR-7 遮蔽 | `mask::same_chunk` | U | 单块内的密钥被替换 |
| FR-7 | `mask::split_across_chunks` | U | 密钥被 1 字节/边界切分仍被替换（核心回归） |
| FR-7 | `mask::short_values_untouched` | U | 长度 < 8 的值不被遮蔽（避免毁掉 "true"） |
| FR-7 | `mask::no_masking_flag` | C | `--no-masking` 原文透出 |
| FR-8 同步 | `e2e::two_devices_converge` | E | A 写→push；B pull 后可见同值 |
| FR-8 | `e2e::disjoint_changes_automerge` | E | 两端各加一条 → 同步后两条都在，无冲突 |
| FR-8 | `e2e::no_op_sync` | E | 无变化时 `sync` 报 `up_to_date` 且不产生提交 |
| FR-9 冲突 | `merge::rule_table` | U | 需求 §11.1 七条规则逐条断言 |
| FR-9 | `merge::determinism` | U | 同输入跑 100 次字节一致 |
| FR-9 | `merge::conflict_id_reproducible` | U | 两台设备独立合并同一分歧 → 冲突条目 **ID 相同** |
| FR-9 | `merge::delete_vs_edit_keeps_edit` | U | 一边删一边改 → 保留改动且标记冲突 |
| FR-9 | `merge::purge_tombstone` | U | purge 过的条目不会被对端复活 |
| FR-9 | `e2e::same_entry_conflict` | E | 两端改同一条 → 双方值都还在，`conflicts` 有记录 |
| FR-9 | `e2e::resolve_take_theirs` | E | `resolve --theirs` 后冲突消失且值正确 |
| FR-10 设备 | `crypto::identity_roundtrip` | U | 生成→序列化→解析 → 同一公钥 |
| FR-10 | `crypto::identity_perms` | U | `identity.key` 落盘为 0600 |
| FR-10 | `e2e::device_revoke` | E | `devices rm B` 后，B 用旧身份无法解密新 vault（退出 4） |
| FR-10 | `e2e::device_add_roundtrip` | E | `devices add` 后新设备可解密 |
| FR-11 恢复 | `crypto::recovery_roundtrip` | U | passphrase 加密→解密得回引导身份 |
| FR-11 | `e2e::bootstrap_from_remote` | E | 空机器 `init --from <repo>` + 恢复密码 → 全部条目可用 |
| FR-11 | `e2e::wrong_recovery_passphrase` | E | 错误密码 → 退出 4，不留下半成品状态 |
| FR-12 审计 | `audit::no_plaintext` | U | 日志行永不包含任何字段值 |
| FR-12 | `contract::audit_records_read` | C | `read` 后日志新增一条，含条目 ID 不含值 |
| FR-15 令牌 | `token::verify_and_scope` | U | 正确令牌通过；错误令牌拒绝；过期拒绝 |
| FR-15 | `token::allow_list_enforced` | C | 令牌未授权条目 → 退出 8 |
| FR-15 | `token::scope_blocks_write` | C | 带令牌执行 `set/edit/rm/resolve` → 退出 7（令牌只读） |
| FR-15 | `token::scope_cannot_be_bypassed_by_injection` | C | 受限令牌 `run --with X=akey://<越权条目>/credential -- sh -c 'echo $X'` → 退出 8 且无明文（关键回归） |
| FR-15 | `token::export_is_scoped` | C | 带令牌 `export` 只含作用域内条目 |
| FR-15 | `token::deny_reveal` | C | 带 `--deny-reveal` 的令牌做 `--reveal` → 退出 7 |
| FR-15 | `contract::token_shown_once` | C | `token create` 输出明文一次；`token list` 不含明文 |
| FR-16 MCP | `contract::mcp_no_values` | C | `mcp` 的 list 工具响应**不含**任何明文值 |
| FR-17 AGENTS.md | `contract::agents_md_shipped` | C | 仓库根有 `AGENTS.md` 且含 `akey run` 示例 |
| FR-13 医生 | `contract::doctor_json` | C | 输出含 `identity/remote/permissions/conflicts/tokens` 段 |
| NFR-5 原子性 | `store::atomic_write_crash` | U | 写到一半失败 → 原文件完好，无残留临时文件 |
| NFR-5 | `store::lock_excludes` | U | 持锁时第二个写操作超时 → `locked` |
| NFR-2 性能 | `bench::hot_path`（`--ignored`） | U | `get` 单次 < 100ms（10³ 条目 vault） |
| NFR-9 日志 | `.*::no_secret_in_any_output` | C | 见 §3 的全局断言 |

## 2. 端到端夹具

`tests/e2e_sync.rs` 用两个临时 HOME 模拟两台机器：

```rust
struct Device { home: TempDir, repo: TempDir, bin: assert_cmd::Command }
// setup: 建 bare 远端（git init --bare）、device A init --remote、device B init --from
```

- 全部 git 操作走本地 `file://` 远端，**不触网**。
- 每个测试独立 `TempDir`，可并行。
- 设置 `GIT_CONFIG_GLOBAL=/dev/null` 与固定 `user.name/email`，隔离开发者本机配置。

## 3. 全局不变式（每个契约测试都附带断言）

1. 任何命令的 stdout 上，**永不出现**任何字段值（除非显式 `--reveal` 或 `read`）。
2. 任何退出非 0 的场景，stdout 为空或合法 JSON；诊断只在 stderr。
3. `--json` 下 stdout 恒为**单个** JSON 文档，无额外输出。
4. 任何命令在任何失败路径后，`vault.age` 要么是旧的完好版本，要么是新的完好版本——不存在中间态。

## 4. 测试替身与边界

| 边界 | 构造 |
|---|---|
| scrypt 慢 | 引导类测试只跑一次；其余用已引导好的夹具 |
| 时间 | `expires_at` / TTL 用固定过去的/未来的时间戳，不 sleep |
| git | 只用本地 bare repo；不 mock，直接跑真 git（快且真） |
| 遮蔽跨块 | 直接对 `Masker` 喂 1 字节分块，不做进程级构造 |
| 权限位 | `#[cfg(unix)]`，`chmod` 后断言行为 |

## 5. 不测什么

- 不测 `age` 自身加密强度（上游职责）。
- 不测 clap 的 help 文案（除非它是契约的一部分：`schema` 输出）。
- 不做 UI/快照测试；不做覆盖率数字目标。
- 不 mock `git`：mock 会掩盖真实的凭据/分叉行为。
