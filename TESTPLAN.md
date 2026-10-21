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
| FR-22 生成器 | `generator::recipe_tokens_combine_with_OR` | U | 每个 token 接受并并集；非法 token 拒（exit 2） |
| FR-22 | `generator::no_ambiguous_excludes_lookalike_characters` | U | 抽样 10k 不出现 `0 O 1 l I |` |
| FR-22 | `generator::hex_base32_base64_each_use_their_own_pool` | U | 字符集一一对应；长度恒等于 recipe length |
| FR-22 | `generator::passphrase_draws_from_eff_wordlist` | U | 词数 = N；只含 `[a-z-]`；词表 ≥ 1024 |
| FR-22 | `contract::generate_standalone_command_does_not_touch_vault` | C | 无 vault 也能跑；退出 0；stdout 是密码单行 |
| FR-22 | `contract::generate_value_never_lands_in_stderr_or_audit` | C | 全部 stdout、零 stderr；audit 文件未创建 |
| FR-22 | `contract::generate_json_envelope_is_ok_data_password` | C | `--json` 输出 `{"ok":true,"data":{"password":"…"}}` 单信封 |
| FR-22 | `set::set_generate_password_keeps_backward_compat` | U | `akey set x --generate-password`（空 recipe）= `letters,digits,symbols,32` |
| FR-23 恢复 UX | `admin::recovery_set_respects_min_passphrase_len_flag` | U | `--min-passphrase-len 16` 时 12 字符被拒（exit 2） |
| FR-23 | `admin::recovery_status_emits_envelope_without_passphrase` | C | `--json` 形状固定；子串检索：不含任何输入的密码 |
| FR-23 | `admin::recovery_unlock_still_fails_with_exit_4_on_wrong_passphrase` | U | 错误密码 → exit 4（与 `--min-passphrase-len` 错误区分） |
| FR-24 审计 | `audit::weak_detects_short_or_single_charset_secrets` | U | 三条规则各自命中至少一个 fixture；fixture 集无 false positive |
| FR-24 | `audit::reused_groups_two_entries_sharing_value_hash` | U | 同值不同条目成对；同值同条目不重复 |
| FR-24 | `audit::stale_flags_rotations_older_than_365d` | U | 366 d 报 stale；180 d 不报；非 apikey/token 不报 |
| FR-24 | `audit::doctor_includes_new_probes_with_stable_names` | C | `checks` 数组含 `weak_secrets`/`reused_secrets`/`stale_rotations`/`expiring` |
| FR-24 | `contract::audit_envelope_carries_no_value_or_hash` | C | `audit --json` 输出全文 substring 检索：任何 fixture 中的值与哈希都不出现 |
| FR-24 | `contract::audit_check_never_includes_value_or_hash` | C | `doctor --json` 的 `checks[].detail` 同样不含值/哈希 |
| FR-25 `Password` 分类 | `model::category_password_has_default_secret_field_password` | U | `builtin_fields == [("password", Concealed)]`；`default_secret_field == "password"` |
| FR-25 | `model::all_categories_length_is_8` | U | `ALL_CATEGORIES.len() == 8`；包含 `Password` |
| FR-25 | `contract::template_list_includes_password` | C | `akey template list --json` 含 `password` 一行 |
| FR-25 | `entries::set_password_creates_with_single_concealed_field` | U | `akey set demo --category password --generate-password=letters,16` → 单字段 `password` (Concealed) |
| FR-25 v1→v2 | `migrate::v1_to_v2_is_identity_on_entries_tokens` | U | 迁移后 entries/tokens/purged 与原 v1 集合一致（按 ID） |
| FR-25 v1→v2 | `migrate::v1_to_v2_bumps_version` | U | 迁移后 `version == 2` |
| FR-25 v1↔v2 合并 | `merge::v1_v2_merge_picks_max_version_and_unions_entries` | U | `(v1 empty, v2 with one entry)` → 输出 `version == 2`，含那条 |
| FR-25 store | `store::load_migrates_v1_in_place` | U | 写入 `version: 1` 的 vault.age → `load` → 写出 `version: 2`；条目不变 |
| FR-25 | `contract::old_vault_loads_without_data_loss` | C | 旧的 fixture v1 vault 经 `load` 后条目数 / 字段数 / 默认秘密字段全部不变 |

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
| NFR-5 锁超时 | `paths::write_lock_times_out_with_locked_while_another_holder_is_active` | U | `with_write_lock` 的超时此前不可测（`LOCK_TIMEOUT` 是常量）。抽出 `timeout` 参数后，竞争路径可在毫秒级断言。 |
| FR-22 生成器 | `generator::*`（上 7 行） | 一开始就没有测试；本轮次次补齐。 |
| FR-23 恢复 UX | `recovery::*`（上 3 行） | 旧 `recovery_unlock_verifies_the_bootstrap_can_open_the_vault` 只测「对密码解得开」，没测「短密码被拒」。补齐。 |
| FR-24 审计 | `audit::*`（上 6 行） | 旧的 `doctor_json_reports_every_probe_with_a_known_status` 只钉状态集合，没钉新四探针的命名 / 输出是否含敏感字段。补齐。 |
| FR-25 Password + v2 | `migrate::*`/`merge::v1_v2_*`/`store::load_migrates_v1_in_place` | 旧的迁移测试集为空——从来没有迁移发生过。引入 v2 后**必须**有这些测试，否则未来再做 v3 时无法回归。 |

### 6.1 v0.4 GUI（`akey-gui`）

GUI 的渲染层（GPUI）与逻辑层分开编译：`backend` / `model` 不依赖 `gpui`，因此下列测试在**没有 Metal 工具链**的机器上也能跑（`cargo test -p akey-gui`，默认 features）。GPUI 视图只做布局，不含可断言逻辑。

| 需求 | 测试 | 层 | 断言什么 |
|---|---|---|---|
| FR-27 定位 | `backend::locate_prefers_env_override` | U | `AKEY_GUI_BIN` 存在时优先；否则找 `PATH`；都没有 → 明确错误 |
| FR-27 定位 | `backend::locate_reports_missing_binary_with_a_hint` | U | 错误文本含 `AKEY_GUI_BIN`，不含 panic |
| FR-27 信封 | `backend::parses_ok_envelope_into_data` | U | `{"ok":true,"data":{…}}` → `Outcome::Ok(Value)` |
| FR-27 信封 | `backend::parses_err_envelope_with_code_and_hint` | U | `{"ok":false,"error":{code,message,hint}}` + 退出码 → `Outcome::Failure` |
| FR-27 信封 | `backend::failure_keeps_stdout_empty_contract` | U | 非 0 退出 + 空 stdout → Failure 而非解析错误 |
| FR-27 stdin | `backend::passes_secret_on_stdin_never_argv` | U | stub 断言参数里**不含**秘密；秘密只能从 stdin 读到 |
| FR-27 边界 | `backend::nonzero_exit_with_unparseable_stderr_does_not_panic` | U | 垃圾 stderr → 结构化错误，不 panic |
| FR-28 启动 | `app::startup_decision_maps_exit_4_to_the_init_prompt` | U | 退出 4 → `Startup::Uninitialized`；0 → `Startup::Ready` |
| FR-29 列表 | `model::list_payload_maps_to_rows` | U | `data.entries[]` → `Vec<Row>`；字段名与 CLI 契约一致 |
| FR-29 详情 | `model::detail_payload_maps_concealed_and_reference` | U | `concealed: true` + `reference` 保留；值不进 `Row` |
| FR-30 揭示 | `model::reveal_is_not_reachable_without_an_explicit_call` | U | 从 `get --json`（无 `--reveal`）解析出的结构**不含**明文 |
| FR-30 揭示 | `backend::reveal_denied_surfaces_as_a_policy_result` | U | stub 退出 7 → `Outcome::Failure { code: 7 }`，界面可显示「被策略拒绝」 |
| FR-31 明文 | `revealed::value_is_dropped_on_hide_and_never_debug_printed` | U | `Revealed` 无 `Debug` 泄漏；`hide()` 后取值不可达 |
| FR-31 明文 | `revealed::value_is_dropped_on_entry_switch` | U | 切到另一条目 → 前一个 `Revealed` 被清 |
| FR-31 字段隔离 | `revealed::a_reveal_is_bound_to_one_field` | U | 同条目的另一字段不能读到已揭示值 |
| FR-31 argv | `backend::write_path_never_places_a_value_in_argv` | U | `set` 的调用参数列表里不含用户输入的值 |
| FR-27 写失败 | `verbs::mutation_failures_are_not_reported_as_rust_success` | U | CLI 非零退出不会被 GUI 当成成功状态 |
| FR-26 依赖图 | `contract::cli_dependency_graph_is_unaffected_by_the_gui` | C | 根 crate 的 `Cargo.toml` 不含 `gpui`；`[workspace] members = ["gui"]` 存在 |

### 6.2 Harness 安装（v0.2 增补）

`agent::*` 单元测试全部使用临时 HOME，且以 `NativeMode::Disabled` 或 `NativeMode::Path`
注入伪 CLI，**从不调用**开发者本机真实的 `claude` / `codex` / `hermes` / `opencode`。
Cursor / Kiro / Devin 没有原生写入器，测试同时断言它们的 `native_cli` 为 `None`，
安装路径不会寻找可执行文件。

| 需求 | 测试 | 层 | 断言什么 |
|---|---|---|---|
| FR-32 | `agent::installing_twice_changes_nothing_the_second_time` | U | 第二次安装 `changed=false`，MCP 与 skill 均为 `unchanged` |
| FR-32 全有或全无 | `agent::a_conflict_on_any_harness_stops_the_whole_install` | U | 任一 harness 有冲突条目 → 另一个 harness 的文件也未被写 |
| FR-32 原生边界 | `agent::the_native_cli_is_not_used_to_replace_an_entry` | U | 仅 `Added` 走原生 CLI；`Replaced` 走结构化配置编辑 |
| FR-32 原生核实 | `agent::a_harness_cli_that_writes_nothing_is_not_believed` | U | CLI 退 0 但配置仍无可用条目 → `harness` 错误 |
| FR-32 共享 skill | `agent::a_shared_skill_is_counted_once_in_the_install_total` | U | Codex + OpenCode 共用 `~/.agents/skills` 时总数按真实文件计 |
| FR-32 纯 stdio | `agent::config::tests::plain_entries_have_no_type_and_reject_disabled` | U | Cursor / Kiro / Devin 写入 `command`+`args` 且无 `type`；`disabled: true` 冲突，`--force` 后消失 |
| FR-32 原生可选 | `agent::registry::tests::config_only_harnesses_have_no_native_writer` | U | 注册表声明 `native_cli` 与 `native_args` 一致；三个新 harness 均为 `None` |
| FR-32 打印一致 | `agent::printed_snippets_are_byte_identical_to_a_fresh_install` | U | `agent print` 的片段与首次安装写入的字节一致 |
| FR-32 卸载镜像 | `agent::uninstall_removes_everything_install_wrote_and_is_idempotent` | U | 安装写的内容全部移除；配置文件保留；重跑 `changed=false` |
| FR-32 卸载共享 skill | `agent::uninstall_deduplicates_a_shared_skill_and_warns_about_it` | U | Codex + OpenCode 共用的 skill 只删一次，行级报告带 `shared_with` |
| FR-32 卸载全有或全无 | `agent::a_conflict_on_any_harness_stops_the_whole_uninstall` | U | 任一 harness 冲突 → 其他 harness 未被改动；`--force` 后才全部移除 |
| FR-32 卸载 dry run | `agent::uninstall_dry_run_deletes_nothing` | U | `--dry-run` 报告将移除的文件，磁盘不变 |
| FR-32 卸载分层 | `agent::uninstall_can_remove_one_layer` | U | `--only mcp` 只删注册，skill 保留 |
| FR-32 配置移除 | `agent::config::tests::uninstall_preserves_unrelated_settings` | U | 只删 `akey` 条目，注释与无关键保留 |
| FR-32 配置移除边界 | `agent::config::tests::uninstall_never_rewrites_a_malformed_file` | U | 配置无法解析 → 报错且文件字节不变 |
| FR-32 skill 移除边界 | `agent::skill::tests::uninstall_requires_force_for_an_unmanaged_skill_and_keeps_foreign_files` | U | 非 akey 的 skill / sidecar 不动，需 `--force` |
| FR-32 无 vault | `contract::agent_install_works_without_a_vault_and_is_idempotent` | C | 未初始化也可安装；重跑幂等；stdout 仍是单信封 |
| FR-32 纯 stdio 契约 | `contract::agent_install_supports_plain_stdio_harnesses` | C | Cursor / Kiro / Devin 无需原生 CLI 即可安装；配置无 `type`；`status` 报 `native.command = null`；卸载保留配置文件 |
| FR-32 卸载契约 | `contract::agent_uninstall_removes_only_its_own_artifacts_and_is_idempotent` | C | 只删自己的产物；配置文件保留；重跑 no-op；JSON 键稳定 |
| FR-32 选择 | `contract::agent_install_requires_a_selection` · `contract::agent_uninstall_requires_a_selection` | C | 不点名且无 `--all` → exit 2（`usage`） |
| FR-32 文档覆盖 | `contract::agent_documentation_covers_every_command` | C | README 的命令索引包含 `agent` |
