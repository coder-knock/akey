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
| FR-1 条目模型 | `model::name_validation_accepts_and_rejects_expected_forms` | U | 合法名通过；大写/空格/前导 `-` 拒绝 |
| FR-1 | `model::concealed_types_cover_secret_bearing_fields` | U | `Concealed/Notes/SshKey` → true，其余 false |
| FR-3 信封 | `contract::json_success_is_a_single_ok_envelope_on_stdout` | C | stdout 是 `{"ok":true,"data":…}` 合法 JSON |
| FR-3 | `contract::failure_writes_nothing_to_stdout` | C | 失败时 stdout 为空、stderr 有诊断、退出码正确 |
| FR-3 | `contract::human_mode_keeps_diagnostics_off_stdout` | C | 诊断绝不污染 stdout（用管道分别抓取） |
| FR-3 | `contract::exit_codes_match_the_documented_contract` | C | 12 个错误场景各自映射到 2/3/4/5/6/7/8/1 |
| FR-3 | `contract::commands_never_block_waiting_for_input` | C | 非 TTY 下任何命令不阻塞等待输入（超时即失败） |
| FR-3 | `contract::set_repeated_with_the_same_value_is_a_no_op` | C | 同一条 `set` 连跑 3 次：条目 ID、`created_at`、`updated_at` 与字段集合全不变，条目数仍为 1（`vault.age` 的字节稳定性无法断言——age 每次重新随机化密文） |
| FR-4 暴露控制 | `contract::get_conceals_secrets_and_exposes_references_instead` | C | `get` 输出含 `••••`，且**不含**明文串 |
| FR-4 | `contract::entry_can_be_pinned_to_deny_reveal` | C | `reveal=deny` 时 `--reveal` 退出 7 |
| FR-4 | `contract::inject_cannot_route_around_a_global_reveal_ban` | C | `AKEY_NO_REVEAL=1` 下 `--reveal` 退出 7（run 侧另见 `contract::run_refuses_no_masking_while_reveal_is_forbidden`） |
| FR-4 | `contract::get_conceals_secrets_and_exposes_references_instead` | C | 隐藏值的同时给出 `reference` 串 |
| FR-5 引用 | `reference::parse_table_accepts_valid_forms` | U | 表驱动：合法/非法、可选 vault、section、query（拒绝用例见 `reference::parse_table_rejects_invalid_forms`） |
| FR-5 | `reference::parse_in_expands_variables` | U | `$APP_ENV` 展开；未定义变量 → usage |
| FR-5 | `reference::resolve_returns_each_attribute` | U | 名字与 ID 都能命中；均不存在 → not_found（ID 单列见 `reference::resolve_by_id_reference_addresses_the_same_entry`） |
| FR-5 | `reference::find_field_is_section_scoped` | U | 同名跨 section → ambiguous |
| FR-6 注入 | `contract::run_injects_a_secret_into_the_child_and_masks_any_echo` | C | 子进程读到明文；调用者 stdout 无明文 |
| FR-6 | `contract::run_reads_references_out_of_an_env_file` | C | `--env-file` 中的引用被解析 |
| FR-6 | `run::precedence_is_with_then_bundle_then_env_file_then_process_env` | C | env-file 覆盖 shell 环境变量 |
| FR-6 | `contract::run_passes_through_the_child_exit_code` | C | 子进程退 42 → akey 退 42 |
| FR-7 遮蔽 | `mask::same_chunk` | U | 单块内的密钥被替换 |
| FR-7 | `mask::split_across_chunks_byte_by_byte` | U | 密钥被 1 字节/边界切分仍被替换（核心回归） |
| FR-7 | `mask::short_values_untouched` | U | 长度 < 8 的值不被遮蔽（避免毁掉 "true"） |
| FR-7 | `run::unmasked_output_passes_the_plaintext_through` | C | `--no-masking` 原文透出 |
| FR-8 同步 | `e2e::a_second_device_reads_what_the_first_stored` | E | A 写→push；B pull 后可见同值 |
| FR-8 | `e2e::edits_to_different_entries_merge_without_conflict` | E | 两端各加一条 → 同步后两条都在，无冲突 |
| FR-8 | `e2e::a_second_sync_with_nothing_to_do_reports_up_to_date` | E | 无变化时 `sync` 报 `up_to_date` 且不产生提交 |
| FR-9 冲突 | `merge::rule_both_changed_differently_keeps_ours_and_copies_theirs` | U | 需求 §11.1 七条规则逐条断言（逐条用例为 merge::rule_* 一组，此处取冲突规则） |
| FR-9 | `merge::determinism_same_input_same_bytes` | U | 同输入跑 100 次字节一致 |
| FR-9 | `merge::conflict_id_reproducible_across_devices` | U | 两台设备独立合并同一分歧 → 冲突条目 **ID 相同** |
| FR-9 | `merge::delete_vs_edit_keeps_edit_and_records_conflict` | U | 一边删一边改 → 保留改动且标记冲突 |
| FR-9 | `merge::purge_tombstone_suppresses_resurrection` | U | purge 过的条目不会被对端复活 |
| FR-9 | `e2e::conflicting_edits_keep_both_sides_and_are_resolvable` | E | 两端改同一条 → 双方值都还在，`conflicts` 有记录 |
| FR-9 | `e2e::conflicting_edits_keep_both_sides_and_are_resolvable` | E | `resolve --theirs` 后冲突消失且值正确（同上一条用例的后半段；单元层见 `entries::conflicts_and_resolve_both_sides`） |
| FR-21 信任集合 | `e2e::an_injected_recipient_never_receives_ciphertext` | E | 远端写权限者塞进 `recipients.json` 的公钥被报为 pending，且始终退出 4、零明文（**A1 回归**） |
| FR-21 | `e2e::trusting_a_recipient_lets_it_decrypt` | E | `devices trust` 后可读；`devices untrust` 后新密文又读不到 |
| FR-21 | `store::refuses_to_write_when_this_device_is_untrusted` | U | 本机不在信任集合时拒绝写入 |
| FR-10 设备 | `identity::generate_save_load_keeps_the_same_pubkey` | U | 生成→序列化→解析 → 同一公钥 |
| FR-10 | `identity::save_writes_0600_and_load_rejects_other_readable_file` | U | `identity.key` 落盘为 0600 |
| FR-10 | `e2e::a_revoked_device_can_no_longer_open_the_vault` | E | `devices rm B` 后，B 用旧身份无法解密新 vault（退出 4） |
| FR-10 | `e2e::a_second_device_reads_what_the_first_stored` | E | `devices add` 后新设备可解密（夹具中第二台设备经 `init --from` 加入、`devices trust` 后才可读） |
| FR-11 恢复 | `admin::recovery_unlock_verifies_the_bootstrap_can_open_the_vault` | U | passphrase 加密→解密得回引导身份 |
| FR-11 | `e2e::a_second_device_reads_what_the_first_stored` | E | 空机器 `init --from <repo>` + 恢复密码 → 全部条目可用（夹具 `pair()` 即此路径） |
| FR-11 | `e2e::a_wrong_recovery_passphrase_cannot_join` | E | 错误密码 → 退出 4，不留下半成品状态 |
| FR-12 审计 | `audit::log_never_contains_secret_material` | U | 日志行永不包含任何字段值 |
| FR-12 | `contract::audit_log_records_actions_without_secrets` | C | `read` 后日志新增一条，含条目 ID 不含值 |
| FR-15 令牌 | `token::issued_token_verifies_and_wrong_token_is_rejected` | U | 正确令牌通过；错误令牌拒绝；过期拒绝（过期/吊销另见 `token::expired_and_revoked_tokens_are_locked`） |
| FR-15 | `contract::token_scope_violation_is_exit_8` | C | 令牌未授权条目 → 退出 8 |
| FR-15 | `contract::a_token_cannot_write` | C | 带令牌执行 `set/edit/rm/resolve` → 退出 7（令牌只读） |
| FR-15 | `contract::token_scope_cannot_be_bypassed_by_injection` | C | 受限令牌 `run --with X=akey://<越权条目>/credential -- sh -c 'echo $X'` → 退出 8 且无明文（关键回归） |
| FR-15 | `contract::export_under_a_token_only_covers_the_scope` | C | 带令牌 `export` 只含作用域内条目 |
| FR-15 | `contract::inject_cannot_route_around_a_deny_reveal_token` | C | 带 `--deny-reveal` 的令牌做 `--reveal` → 退出 7 |
| FR-15 | `admin::token_create_shows_plaintext_once_and_list_never_does` | C | `token create` 输出明文一次；`token list` 不含明文 |
| FR-16 MCP | `contract::mcp_speaks_json_rpc_and_never_returns_values` | C | `mcp` 的 list 工具响应**不含**任何明文值 |
| FR-17 AGENTS.md | `contract::init_ships_agent_documentation_into_the_vault_repo` | C | 仓库根有 `AGENTS.md` 且含 `akey run` 示例 |
| FR-13 医生 | `contract::doctor_json_reports_every_probe_with_a_known_status` | C | `checks` 非空；每项的 `status` ∈ `ok/warning/error` 且有 `detail`；必含 `identity_permissions`、`repository`、`remote`、`vault`、`conflicts`、`tokens` 六项探针 |
| NFR-5 原子性 | `paths::replacing_a_file_never_exposes_a_partial_state` | U | 写到一半失败 → 原文件完好，无残留临时文件（残留文件检查见 `paths::atomic_write_leaves_no_temp_files_behind`） |
| NFR-5 | `paths::write_lock_times_out_with_locked_while_another_holder_is_active` | U | 另一持有者未释放时，写者在超时后返回 `locked`（退出 4）；释放后可再次取得 |
| NFR-2 性能 | `store::hot_path_stays_under_100ms_with_a_thousand_entries`（`--ignored`） | U | `get` 单次 < 100ms（10³ 条目 vault） |
| NFR-9 日志 | `contract::list_never_carries_field_values` | C | 见 §3 的全局断言（无单条聚合用例，由各契约用例与 `audit::log_never_contains_secret_material` 内联断言） |

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

## 6. 曾列出、现已补齐的缺口

§1 曾有三行标注 `未实现`：它们是写代码前列出的验收项，但没有任何测试覆盖。现已全部补齐——其中第一项还牵出一个真实缺陷。

| 需求 | 测试 | 补齐过程中 |
|---|---|---|
| FR-3 幂等 set | `contract::set_repeated_with_the_same_value_is_a_no_op` | **发现缺陷**：内容未变的重复写入也会推进 `updated_at`。该字段是 `sync` 裁决合并胜负、以及派生冲突副本 ID 的输入，所以一次重试会让本机陈旧内容赢过对端的真实修改，并让两台设备对同一分歧推导出不同 ID。已改为仅在内容真正变化时推进（`apply_set` / `apply_edit`）。 |
| FR-13 医生 | `contract::doctor_json_reports_every_probe_with_a_known_status` | 计划写的"五个段"实际实现为命名探针清单（`checks[].name`），文档随之更正。 |
| NFR-5 锁超时 | `paths::write_lock_times_out_with_locked_while_another_holder_is_active` | `with_write_lock` 的超时此前不可测（`LOCK_TIMEOUT` 是常量）。抽出 `timeout` 参数后，竞争路径可在毫秒级断言。 |
