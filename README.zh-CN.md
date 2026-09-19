# akey

**给 AI agent 用的加密凭证库。** 一个 Rust 单二进制 CLI，密文通过一个 git 远程仓库在多台设备间同步。

> English: [README.md](README.md) · [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md)

它解决的核心问题是：**让 agent 能使用密钥，但从不看见密钥。**

```bash
# agent 需要调 OpenAI，但明文永远不进它的上下文
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS https://api.openai.com/v1/models
```

子进程拿到了真值；agent 的 stdout 里只有 `<concealed by akey>`。

---

## 为什么不是 `.env`

| | 明文 `.env` | akey |
|---|---|---|
| AI 读到 key | 会（进了上下文就收不回） | 不会，只有子进程能拿到 |
| 多台机器 | 手动同步 | `akey sync` |
| 静态加密 | 无 | 有（age / X25519 + ChaCha20-Poly1305） |
| 设备丢失 | 挨个改 key | `akey devices rm <那台>`，它当场失效 |
| 给 CI 降权 | 只能给全量 key | `akey token create --allow openai --ttl 30d` |
| 操作留痕 | 无 | `akey log` |

---

## 装

```bash
cargo build --release        # 产出单个二进制，无 OpenSSL、无守护进程
install -m755 target/release/akey /usr/local/bin/akey
```

运行期唯一的外部依赖是 `git`（用于同步）。所有命令除 `sync` 外都离线可用。

## 五分钟上手

```bash
# 1. 建库（不给 --remote 就是纯本地库）
akey init --remote git@github.com:you/akey-vault.git --device macbook --recovery
#    --recovery 让你以后能在新机器上用一句密码引导进来

# 2. 存一个 key（秘密走 stdin，不进 shell 历史）
printf 'credential=sk-...\n' | akey set openai --category apikey --stdin

# 3. 看看有什么（只出元数据，不出值）
akey list

# 4. 用它 —— 这是给 AI 用的主要姿势
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models

# 5. 换台机器
akey init --from git@github.com:you/akey-vault.git --device laptop   # 会问恢复密码
```

## 命令一览

| 类别 | 命令 |
|---|---|
| 生命周期 | `init` · `devices` · `recovery` · `token` · `sync` · `conflicts` · `resolve` |
| 条目 | `get` · `set` · `edit` · `rm` · `restore` · `cp` · `mv` · `list` · `template` · `doc` |
| 交付（给 agent） | `run` · `inject` · `read` · `mcp` |
| 运维 | `whoami` · `doctor` · `log` · `schema` · `completion` |
| 迁移 | `export` · `import` |

机器可读的完整清单：`akey schema --json`。本文档不重复它，**agent 应当以 `schema` 为准**。

## 安全模型，三句话

1. **每台设备一把 X25519 私钥**，只存在本机（`0600`），永不进 git。金库用所有未吊销设备的公钥加密。
2. **热路径不做 KDF**。日常命令只有 X25519 + ChaCha20-Poly1305，微秒级；scrypt 只在 `init` / `recovery` 时跑一次。
3. **取明文是显式的、可被拒的**。`get` 默认隐藏，`read` 是明文通道，两者都受条目策略、`AKEY_NO_REVEAL`、能力令牌三重约束。

丢掉笔记本：`akey devices rm <名字>` 会在下次同步时重新加密，那台机器再也解不开新版本。

## 文档

| | 读者 | 内容 |
|---|---|---|
| **[docs/AGENT-INTEGRATION.zh-CN.md](docs/AGENT-INTEGRATION.zh-CN.md)** | **AI agent** | 怎么接、怎么用、出错怎么自愈、什么绝对不能做 |
| **[SKILL.md](SKILL.md)** | **agent harness** | 可直接加载的 skill 定义（带触发条件） |
| **[docs/SECURITY.zh-CN.md](docs/SECURITY.zh-CN.md)** | **安全评估者** | 威胁模型、攻防模拟、发现清单与状态 |
| [AGENTS.md](AGENTS.md) | 改这个仓库的 agent | 架构、约定、不可动的契约 |
| [REQUIREMENTS.md](REQUIREMENTS.md) | 人 | 需求与对外契约，含与 1Password CLI 的功能对标 |
| [DESIGN.md](DESIGN.md) | 人 | 数据模型、磁盘格式、算法、错误码 |
| [TESTPLAN.md](TESTPLAN.md) | 人 | 每层该断言什么 |

英文版：`README.md` · `docs/AGENT-INTEGRATION.md` · `SKILL.md`。
规范三件套（REQUIREMENTS / DESIGN / TESTPLAN）目前只有中文。

金库仓库里会自带一份 `AGENTS.md`（`akey init` 写入），所以换台机器 clone 下来，agent 也能自举。

## 状态

CLI 完整可用：185 单元 + 33 契约 + 8 端到端测试，`cargo clippy` 零警告，release 二进制 4.0 MB。
桌面 GUI（gpuix）是下一轮；`akey mcp` 已可让 agent 直接挂载，只暴露元数据、永不返回值。

## 许可

MIT，见 [LICENSE](LICENSE)。
