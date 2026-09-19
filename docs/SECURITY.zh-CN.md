# 安全评估

> 范围：0.1.0 树上的 `akey` CLI。本文回答那个真正要紧的问题：**能不能被攻破、能不能解出明文？**
>
> 每条结论都标注来源：**[实测]** = 真跑过命令并记录了输出；**[静态]** = 读过代码路径。
> 攻击复现见 §9。

> English: [SECURITY.md](SECURITY.md)

---

## 1. 结论

| 攻击者手里的东西 | 能拿到什么 | 代价 |
|---|---|---|
| 远端仓库的**读**权限 | **什么都读不出。** 只有 `vault.age`（age/X25519）、`recipients.json`（公钥）、`recovery.age`（scrypt）。私钥从不进仓库。 | 只能离线爆破恢复密码，见 §7 |
| 某台设备的本机目录 | **全部。** `identity.key` 就是金库本身。 | 零成本——但这是**声明的信任边界**，不是缺陷 |
| 远端仓库的**写**权限 | **全部，且追溯既往** —— 见 A1 | 一次普通 `git push` |
| 一个受限能力令牌 | 只有 `--allow` 允许的部分 —— **在 §4 的修复之后** | —— |

**净结论**：密码学不是短板。`age` 用得正确，收件人集合在每次加密时都被强制执行，明文从未落盘、从未进仓库。短板在 **CLI 表面的策略执行** 与 **对 `recipients.json` 的无条件信任**。

16 条发现里，12 条已在本轮修复并各自带走回归测试。1 条**仍然敞开且严重**（A1），它需要产品决策而不是打补丁 —— 见 §5。

---

## 2. 设计声称的威胁模型

- 每台设备一把 X25519 私钥在 `~/.config/akey/identity.key`（`0600`），永不进 git。
- `vault.age` 加密给所有未吊销设备 + 一个**引导身份**。
- `recovery.age` 是引导身份的私钥，用 scrypt 以恢复密码加密。
- 远端在**机密性上**被视为不可信：「仓里只有密文」。
- 能力令牌只读、限作用域。

设计**没有**建模的：拥有远端**写**权限的攻击者。那个缺口就是 A1。

---

## 3. 做过的攻击模拟

每条都用 release 二进制 + 两个临时 `HOME` + 一个本地裸仓库真跑过，无 mock。

### 3.1 明文外泄全扫 —— **干净** [实测]

建一个含哨兵值的金库，把 `get` / `get --reveal` / `read` / `list` / `run` / `inject` / `export` /
`doc put` / `doc get` / `edit` / `token create` / `log` / `doctor` / `sync` 全跑一遍，然后扫：

- 金库工作区的每个文件
- **全部 git 对象、全部 revision**（`git grep <哨兵> $(git rev-list --all)`）
- 本机私有目录的每个文件（含 `audit.log`）

**结果：哨兵值在内存解密路径之外，一处都没出现。**

`init` 后的权限位：`$AKEY_HOME` `0700`；`identity.key` / `config.toml` / `audit.log` / `vault.lock` `0600`。[实测]

### 3.2 收件人注入 → 全量明文外泄 [实测] —— **A1，敞开**

```
攻击者: akey init --device attacker             # 一条命令，无任何特权
攻击者: git clone <远端>；改 recipients.json 塞入自己的公钥；git push
受害者: akey sync                                # 静默接受，exit 0，无告警
受害者: akey set openai --stdin; akey sync       # 用「全部活跃收件人」重新加密
攻击者: 把 config.toml 指向 clone；akey read akey://openai/credential
        → sk-ROTATED-AFTER-ATTACK               # 连攻击**之前**写入的条目也一并到手
```

### 3.3 快进路径逆转设备吊销 [实测] —— **A2，已修**

```
alpha: akey devices rm beta                      # beta 离开收件人集合
beta（已被吊销，但仍有 git 写权限）:
       git fetch; git reset --hard origin/main   # 先快进
       改 recipients.json 清掉自己的 revoked_at
       git commit; git push                      # 一次**普通**推送，无需 force
alpha: akey sync                                 # 走快进路径
       → beta 在 alpha 上又变成活跃收件人
alpha: akey set openai --stdin; akey sync
beta:  akey read akey://openai/credential
       → sk-AFTER-REVOKE                         # 一个来回，吊销被撤销
```

根因：`merge_recipients` 实现了「吊销优先」，但**快进分支从来没调用它**——它用远端版本整体替换了工作区，包括 `recipients.json`。

### 3.4 受限令牌 → 提权 [实测] —— **A5，已修**

拿着一个 `--allow openai`、无写权限的令牌：

```
akey --json token create --name pwned            → exit 0   # 铸出了**无限制**令牌
akey --json devices add --name backdoor          → exit 0
akey --json recovery set                         → exit 0   # 植入自己的恢复密码
akey --json set evil --stdin                     → exit 7   # 正确拒绝
akey --json rm openai                            → exit 7   # 正确拒绝
```

`token create` 最致命：被限制在单条目上的令牌可以铸出一个什么都不限制的令牌，然后读全库。作用域自我否定。

### 3.5 明文闸门绕过 [实测] —— **A3 / A4 / A6 / A8 / A9 / A10，已修**

```
AKEY_NO_REVEAL=1 akey read akey://acct/password   → exit 7   # 正确
AKEY_NO_REVEAL=1 akey inject <<< 'x=akey://acct/password'
                                                  → 明文直接出 stdout，exit 0   # A3
entry reveal=deny; akey get acct                  → otp 种子明文打印              # A4
entry reveal=deny; akey export --yes              → 该条目明文被导出              # A6
akey run --no-masking …                           → 在禁 reveal 策略下未被拒       # A8
akey run --with A="Bearer akey://acct/password" -- sh -c 'echo ${A#Bearer }'
                                                  → CANARY-PW-123456             # A9
akey --dry-run read akey://acct/password -o /tmp/x  → 真写了 17 字节             # A10
```

### 3.6 掩蔽的边界 [实测] —— 接受并记录

```
akey run --with S=akey://acct/password -- sh -c 'echo direct=$S'
  → direct=<concealed by akey>
akey run --with S=akey://acct/password -- sh -c 'printf %s "$S" | base64'
  → Q0FOQVJZLVBXLTEyMzQ1Ng==            # 绕过掩蔽
```

掩蔽防的是**误回显**。它不是、也不可能是针对**恶意子进程**的边界：那个进程本来就握着明文，它可以编码、可以拆到 stdout/stderr 两边、可以写 socket。请把 `akey run` 当成人体工学护栏。

### 3.7 MCP 面 —— **干净** [实测]

畸形 JSON → `-32700` 且**不回显 payload**；多余 `arguments` 字段被忽略；冲突副本名 → 只回 `no entry named …`；`tools/call` 只返回 `label`/`type`/`concealed`/`reference`，**永不返回值**。

### 3.8 远端回滚 —— 吊销**扛住了** [实测]

把裸仓库硬回滚到吊销前的提交，**没能**复活被吊销的设备：`merge_recipients` 是粘性的。（这是较弱的变体；§3.3 才是打穿的那条。）

### 3.9 依赖审计 —— **干净** [实测]

`cargo audit` 与 `cargo deny` 在本机跑不起来：本地 advisory-db 含 CVSS 4.0 条目，两个解析器都拒绝。绕开解析器，直接把 `Cargo.lock` 与 advisory 库做匹配。

- 锁文件里 252 个包
- 42 条 RustSec 通告按名字命中我们的依赖
- **0 条影响我们的版本**（全部落在 `patched` / `unaffected` 之内）
- 匹配器用已知已修补的通告做过反向校验（如 `age 0.12.1` 对 RUSTSEC-2024-0433，patched `>= 0.11.1`），所以「零命中」是有意义的

---

## 4. 发现清单

| ID | 严重度 | 发现 | 状态 |
|---|---|---|---|
| **A1** | **严重** | 远端写权限 → 收件人注入 → 追溯既往的全量明文 | **敞开** —— 见 §5 |
| A2 | 高 | 快进路径绕过「吊销优先」；被吊销设备能自我复活 | 已修 + 测试 |
| A3 | 高 | `inject` 是明文出口，却绕过全部 reveal 闸门 | 已修 + 测试 |
| A4 | 高 | `otp` 字段未视为秘密 → TOTP **种子**默认明文打印 | 已修 + 测试 |
| A5 | 高 | 受限令牌可铸无限制令牌、并植入自己的恢复密码 | 已修 + 测试 |
| A6 | 中 | `export` 无视条目级 `reveal=deny` | 已修 + 测试 |
| A7 | 中 | `sync` 用 `git add -A`，误落进仓库的明文会被提交并推送 | 已修 |
| A8 | 中 | 禁 reveal 策略下 `run --no-masking` 未被拒 | 已修 + 测试 |
| A9 | 中 | 组合值（`Bearer <ref>`）只掩整串，裸的那半段外泄 | 已修 |
| A10 | 中 | `--dry-run` 对 `read -o` / `inject -o` 无效，仍写明文文件 | 已修 |
| A11 | 低 | 环境变量/stdin 路径不校验恢复密码长度（下限只作用于 TTY） | 已修 + 测试 |
| A12 | 低 | 非交互下 `recovery rotate` 是静默空转（两次读同一个环境变量） | 已修 + 测试 |
| A13 | 低 | 重复 `recovery set` 会堆积引导身份 | 已修 + 测试 |
| A14 | 信息 | 死面：`Config.reveal_allowed`、`--debug`、`doctor --agent` 均无效果 | 敞开（琐碎） |
| A15 | 信息 | 元数据：设备名、提交时间戳、密文体积泄漏条目量级 | 设计取舍 |
| A16 | 信息 | 掩蔽是护栏不是沙箱（§3.6）；TOTP 动态码按设计会显示 | 设计取舍 |

**查过且确认为健全的**（值得记下的负结论）：

- `age` 用法：多收件人加密、无 nonce 重用、解密失败不返回半截明文、密文非确定性、拒绝零收件人加密。
- 令牌比较是常数时间的（`subtle`）；摘要算法是 SHA-256 over 256 位随机值。
- `identity.key` 从不被打印；`expose_secret()` 的全部调用点只有 `save()` 与 `recovery.age` 的 payload。
- 生产代码在承载值的路径上没有 `unwrap`/`expect`/`panic` → 不存在「panic 倒出明文」。
- 任何点名主体的错误消息点名的都是**条目**，从不带值。

---

## 5. A1 —— 敞开的这条，以及为什么它需要你来定

`recipients.json` 决定谁能解密金库，它由远端分发、被**无条件采纳**，没有认证、没有确认、没有告警。任何能写远端的人加一个公钥，下一次合法写入就会把**整个金库（含历史）**重新加密给那把钥匙。

这击穿了设计的核心承诺。「远端只有密文」对**能读**的远端成立，对**能写**的远端不成立——而被盗的 GitHub 账号、泄漏的 CI 令牌、恶意托管方，都给写权限。

**为什么没有在这里直接打补丁**：每一种修法都会改变产品交互，而这是个属于你的取舍。

| 方案 | 对正常流程的影响 | 强度 |
|---|---|---|
| **(a) 拒绝加密给未批准收件人。** 在 `config.toml` 维护一份**本地、永不同步**的信任集合；新收件人先记为 pending，需要 `akey devices trust <pubkey>`。 | 加一台设备要在**每台其他设备**上多跑一条命令 | 强——攻击者一无所获 |
| **(b) 收件人条目带签名。** 新增设备的那条记录携带一个既有设备私钥的签名。 | 无额外操作 | 最强，但需要签名密钥类型（age 的 X25519 不做签名） |
| **(c) 强制显式接受。** 出现未知收件人时 `sync` 拒绝并以非零退出，直到带 `--accept-recipients` 重跑。 | 一次显式确认 | 防得住静默攻击，防不住「总是点同意」的人 |

**建议：(a)**，可选叠加 (c) 的报告能力。它是本地策略检查，不是新密码学机制，并且与 A2 已经遵循的规则一致：**任何决定访问权限的东西，都不能无条件信任远端。**

在那之前：**请把金库远端当成高价值凭据。** 开 2FA、给能写它的令牌收窄范围、优先私有仓库。`akey doctor` 目前对「未知收件人」一个字都不报——这个缺口应当与修复一并补上。

---

## 6. 残余风险

| | 风险 | 为何接受 |
|---|---|---|
| R1 | `identity.key` 是单点 | 固有：它就是设备本身。`0600` + 每次读取时 `ensure_private` |
| R2 | argv 里的秘密对 `ps` 与 shell 历史可见 | 运行时会告警；文档路径是 `--stdin` |
| R3 | 注入的值活在子进程环境里 | 环境注入的固有性质，与所有 env 方案相同 |
| R4 | 内存里的明文副本未全部清零（age 的 `StaticSecret` 无 `Drop` 清零） | 短命 CLI 进程；只对 core dump / swap / 同 uid ptrace 有意义 |
| R5 | 掩蔽可被重新编码绕过（§3.6） | 已记录；掩蔽不是那条边界 |
| R6 | 元数据泄漏（设备名、时间、条目量级） | 单文件密文设计上就隐藏了条目**名**；git 天然带提交时间 |
| R7 | `age 0.12` 是 pre-1.0，上游自称「仅供测试」 | 已锁版本；格式是稳定的公开规范，且正确性由我们自己的往返测试覆盖 |

---

## 7. 密码学参数 [实测]

| | 值 |
|---|---|
| 金库 | age v1，X25519 收件人，ChaCha20-Poly1305 |
| 恢复 | age passphrase 模式，scrypt |
| scrypt 成本（本机） | 每次猜测 ≈2.0 秒 CPU + 512 MiB（`log_n≈19–20`） |
| 令牌摘要 | SHA-256 over 256 位随机值，常数时间比较 |
| 热路径（1000 条目、300 KB 库） | 最差读取 53.7 ms —— 预算是 100 ms |

在约 1 次猜测/秒/核的前提下，攻击泄漏的 `recovery.age` 的离线成本：

| 恢复密码 | 搜索空间 | 时间 |
|---|---|---|
| 1 字符 | 26 | 瞬间 |
| 6 位小写 | 2.6e8 | 100 核上约 36 天 |
| 12 位小写 | 9.5e16 | 约 300 万年 |
| 6 词 diceware | 2.2e23 | 约 1000 万年 |

所以 12 位下限（A11）是**承重**的：仓库一旦泄漏，恢复密码是**唯一**的防线。请优先用多词短语；12 个人类自选的字符并不等于 12 个字符的熵。

---

## 8. 这份评估是怎么做的

两个只读的 `security-reviewer` 代理分别走代码路径（明文出口；密码学与信任模型），维护者同时对着 release 二进制打黑盒。代理的沙箱只读且断网，因此所有动态结论都由维护者实际执行、并把原始输出回传给它们；它们的静态发现也都在被采纳前做了实测验证。

每条修复都用**重放攻击**来验证，而不是重读补丁。A2 与 A5 都做到了「修前确认可利用、修后确认已死」，并各自留下回归测试（`tests/e2e_sync.rs::revocation_survives_a_fast_forward`、`tests/contract.rs::a_scoped_token_cannot_mutate_admin_state`）。

## 9. 复现

```bash
cargo build --release

# 3.2 收件人注入
#   建两个临时 HOME + 一个裸远端，akey init --remote；在 clone 里把**你自己的**公钥
#   加进 recipients.json 并 push。受害者之后任何一次 akey set + akey sync 都会重新加密给你。

# 3.3 吊销逆转
#   akey devices rm <名字> 之后，让那台设备快进到 origin/main、清掉自己的 revoked_at、
#   提交推送，再到另一台设备 akey sync。

# 3.4 令牌提权
akey --json token create --name narrow --allow openai
AKEY_TOKEN=<token> akey --json token create --name pwned      # 必须 exit 7

# 3.5 明文闸门
printf 'x=akey://acct/password\n' | AKEY_NO_REVEAL=1 akey inject       # 必须 exit 7
akey --dry-run read akey://acct/password -o /tmp/should-not-exist      # 必须不写盘

# 3.9 依赖
cargo audit    # 本地 advisory-db 能解析时；否则直接拿 Cargo.lock 对 RustSec
```
