# `akey` —— 一晚上的入门教程

> 一个场景，一步一步走完。文档里出现的每条命令都已经在你读这份文档的这台机器上跑过；
> 你只需要改不属于秘密的那些值，以及那些是秘密的值。
>
> English: [docs/TUTORIAL.md](TUTORIAL.md)

## 场景

你有**两台机器**（一台笔记本、一台台式），还有一台**AI agent**（Claude Code、Codex、或你用的别的）
跑在台式上。你想让这三方都能用同一把 OpenAI API key，但又**谁都不直接看到明文**。
你希望能在任意一台机器上轮换这把 key，另一台下次同步时就能拿到。
你希望 CI 也能调这个 API，但又不让它拿到和笔记本同等级的信任。

这就是整个产品。下面把它走完。

---

## 0. 准备清单（一分钟）

```bash
akey --version            # ≥ 0.1.0
akey schema --json | head  # 打印机器可读的命令面
git --version              # 只有 sync 走网络
```

选一个你已经拥有的 git 远端：GitHub、Gitee、自建 Gitea 都行。远端里**只有密文**，所以其可见性
在密码学上无所谓——但 private 仓库不会把噪音推到公共 issue tracker 上。下面例子用
`git@github.com:you/akey-vault.git`；换成你的。

两个不是秘密的环境变量，整篇教程里会反复出现。可以放进 rc 文件，没有强制依赖：

| 变量 | 作用 |
|---|---|
| `AKEY_HOME` | 覆盖本机私有目录（默认 `~/.config/akey`） |
| `AKEY_DEVICE_NAME` | `init` 时的默认设备名 |

---

## 第 1 步 —— 在第一台机器上初始化金库

打开笔记本的 shell，跑一条命令：

```bash
akey init \
  --remote git@github.com:you/akey-vault.git \
  --device macbook \
  --recovery
```

`--recovery` 会让 CLI 问你一句恢复密码。至少 12 个字符（更短会被拒——这是规则，不是 bug）。
**笔记本丢了之后，这句密码是你挂载新设备的唯一办法。** 把它存进密码管理器，而不是存进笔记本。

刚才发生了什么，三件事：

- 在 `~/.config/akey/identity.key` 生成了一对新的 X25519 密钥，权限 `0600`。
- 在 `~/.config/akey/repo` 初始化了金库仓库，并推到了你的远端。
- 加了一个**引导身份**进收件人集合，它的私钥被你的密码包成 `recovery.age`。引导身份永远
  不需要重新加密——它始终是金库的收件人。

自检：

```bash
akey whoami --json
```

```json
{"ok":true,"data":{"device":"macbook","devices":1,"entries":0,"home":"/Users/you/.config/akey",
 "pubkey":"age1…","remote":"git@github.com:you/akey-vault.git",
 "repo":"/Users/you/.config/akey/repo","token_scope":null,"tokens":0,"vault":"default"}}
```

如果这里 `whoami` 退出 **4**，说明身份没创建——通常是 `~/.config/akey` 的权限问题。
`akey doctor --json` 会告诉你哪一项检查没通过以及怎么修。

---

## 第 2 步 —— 存第一把 key

动手前先背两条规矩：

1. **秘密走 stdin，不进 argv。** 命令行里出现的内容会进 shell 历史、`ps`、以及终端的审计日志。
2. **名字唯一，ID 稳定。** 名字是你敲的，ID 是 26 位 ULID，重命名之后仍然有效。交互用名字，
   脚本里用 ID。

```bash
printf 'credential=sk-proj-9f2a7c1e4b\n' | \
  akey set openai --category apikey --stdin
```

预期输出：

```
created entry 'openai' (01M2WXY5TV8EQ0NT1PH813DKG1, 2 field(s))
```

两个字段，是因为 `apikey` 模板自带 `credential` 与 `url`。`credential` 是秘密，`url` 是 API 端点
标签——下一步顺手设上：

```bash
akey set openai url=https://api.openai.com/v1
```

看一眼金库：

```bash
akey list --json
```

```json
{"ok":true,"data":{"count":1,"entries":[{
  "category":"apikey","id":"01M2WXY5TV8EQ0NT1PH813DKG1",
  "name":"openai","field_count":2,
  "tags":[],"favorite":false,"expires_at":null,"deleted_at":null}]}}
```

金库是加密的，`list` 只出元数据。要看一个条目**的形状**（字段名、类型、以及你要喂给 `--with`
的引用）：

```bash
akey get openai --json | jq -r '.data.fields[] | "\(.id) (\(.type)) → \(.reference)"'
```

```
credential (concealed) → akey://default/openai/credential
url (url)              → akey://default/openai/url
```

**reference 才是你真正想要的东西。** 明文值不需要、也不该出现在你的 prompt、日志、对话记录里。

---

## 第 3 步 —— 让 agent 用上 key

这是整个产品围绕的核心姿势。**agent 把需要密钥的那条命令包起来；秘密进的是子进程的环境，
不是 agent 的上下文。**

```bash
akey run \
  --with OPENAI_API_KEY=akey://openai/credential \
  -- curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models
```

终端里看到的是模型列表的 JSON。agent 跑同一条命令，看到的也是**完全一样**——没有单独的「agent
通道」。agent 可以把这条命令交给你，秘密仍然不会进它的上下文。

再细一点：就算子进程**试图**把秘密再打回给你，遮蔽器也会拦下来。

```bash
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  sh -c 'echo "got=$OPENAI_API_KEY"'
```

```
got=<concealed by akey>
```

shell 展开**确实发生**了（变量被设了），但在捕获到的输出里，匹配到秘密的那段字节序列被替换了。
**注意**：遮蔽器只对 **8 个字符及以上**的值生效——更短的话会把正常输出（`true`、`0`、
`us-east-1`）打成马赛克。短秘密不要指望 `run` 替你兜底。

`--with` 的其他几种等价写法：

```bash
akey run --with OPENAI_API_KEY=akey://openai/credential -- …   # 显式引用（推荐）
akey run --with OPENAI_API_KEY=openai                -- …     # 简写：取默认秘密字段
akey run --with openai                                -- …    # 变量名由条目名派生 → OPENAI_API_KEY
```

子进程是已有项目、已经有 `.env` 的：

```bash
# .env
OPENAI_API_KEY=akey://openai/credential

akey run --env-file .env -- npm start
```

`--env-file` 把里面每一个 `akey://…` 引用求值后注入到子进程环境。`.env` 本身没有明文，可以放心提交。

---

## 第 4 步 —— 推上去，让台式机能拉到

```bash
akey sync --json
```

```json
{"ok":true,"data":{"result":"pushed","entries":1,"devices":1,"conflicts":0}}
```

第一次推送会让你确认远端（下次用 `-y` 跳过）。之后 `sync` 就一条：拉、合并（必要时）、推。

`sync` 的退出码要背：

| 退出码 | 含义 | 你做什么 |
|---|---|---|
| 0 | 推完 / 拉完 / 已经最新 | 啥也不用做 |
| 5 | 合并产生了冲突副本 | 跑 `akey conflicts --json`，挑一边，再 `sync` |
| 6 | git / 远端坏 | 看一下 `git ls-remote`，退避后重试一次 |

`5` 是最让新手懵的。**数据没丢**——合并已经完成并推送；`ours` 占原名，`theirs` 变成
`<name>.conflict.<短ID>`。退出码 5 是机器在告诉你「得有人挑一边」，不是「你的数据没了」。

---

## 第 5 步 —— 起第二台机器（台式），用上同一把 key

在台式上：

```bash
akey init --from git@github.com:you/akey-vault.git --device desktop
```

这一步会问恢复密码。忘了的话，**就停在这里**——没有备用方案，而这也是 akey 唯一真正无情的设计点。
二进制会做这些事：
- fetch 金库，
- 用你的密码解密 `recovery.age`，
- 生成新的设备身份，
- 把新设备加进 `recipients.json`，
- 重新加密 `vault.age`，把新设备纳入收件人集合，
- commit & push。

然后回到**第一台机器（笔记本）**批准这台新设备。这一步正是挡住「远端塞进恶意公钥」攻击的关：
`recipients.json` 只是个目录，加密只给仓库收件人集合**和**你本机信任集合的**交集**：

```bash
akey devices trust desktop
```

回到台式，key 就能用了：

```bash
akey list
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models | head
```

---

## 第 6 步 —— 轮换 key

在哪台机器上顺手就在哪台。明文依旧走 stdin，跟第 2 步一样：

```bash
printf 'credential=sk-proj-rotated-9c4a\n' | akey set openai --stdin
akey sync                       # 笔记本推上去
```

在台式上，下次 `sync`（或者下次 `run` 触发自动拉取时）就会拿到新值：

```bash
akey sync
akey get openai --json | jq '.data.fields[0].rotated_at'   # 时间戳动了
```

想让元数据明确说「我故意轮换过」（`list` 才能据此标出陈旧的 key）：

```bash
akey edit openai --rotate
```

要让这个条目**永远不允许取明文**（注入依然能用）：

```bash
akey edit openai --reveal-policy deny
```

> **不想自己想一个强密码？** `akey generate` 自带生成器和 diceware 词组 ——
> `akey generate no-ambiguous,24` 或 `akey generate passphrase,5`——见第 10 步。
> 结果可以直接 pipe 给 `set --stdin`。

---

## 第 7 步 —— 给 CI 一个最小权限、只读的能力令牌

你**不会**把设备身份给 CI。CI 拿到的是能力令牌：

- 只能注入 `--allow` 列表里的条目；
- 不能取明文（`--deny-reveal`）；
- 不能改任何东西（写入一律退出 **7**）；
- 到期自动失效。

在笔记本上：

```bash
akey token create --name ci-openai --allow openai --deny-reveal --ttl 30d
```

```
token 'ci-openai' issued — copy it now, it will never be shown again
akey_3plcjEBH0qqPuqo6GW-spn-1Ky-yMLJNLiQ95sZrwcI
```

明文令牌**只回显这一次**。把它放进 CI 的 secret 仓库，命名 `AKEY_TOKEN`：

```yaml
# .github/workflows/example.yml（示例，按你的平台改）
- env:
    AKEY_TOKEN: ${{ secrets.AKEY_TOKEN }}
  run: |
    akey run --with OPENAI_API_KEY=akey://openai/credential -- |
      python ./build_embeddings.py
```

同一个令牌，在 CI 里被调用：

```bash
AKEY_TOKEN=akey_3plc…  akey run --with OPENAI_API_KEY=akey://openai/credential -- …
```

CI 进程**能**做什么、**不能**做什么，验证一遍：

```bash
# ✅  范围内，只注入
AKEY_TOKEN=akey_3plc… akey run --with OPENAI_API_KEY=akey://openai/credential -- …

# ❌  试图写
AKEY_TOKEN=akey_3plc… akey set github --category apikey credential=foo
# → 退出 7，this command is running with AKEY_TOKEN, which is a read-only capability

# ❌  试图直接读明文
AKEY_TOKEN=akey_3plc… akey get openai --reveal
# → 退出 7，denied by --deny-reveal

# ❌  触及不在 --allow 里的条目
AKEY_TOKEN=akey_3plc… akey run --with GITHUB_TOKEN=akey://github/credential -- …
# → 退出 8，token_scope
```

CI 被攻陷时，爆炸半径是：一个条目、最多 30 天。想提前撤销：

```bash
akey token rm ci-openai
```

笔记本下次 `sync` 时立即吊销。被盗的令牌解不开任何新东西；它缓存到内存里的那点值就是
唯一暴露窗口。

---

## 第 8 步 —— agent 实际看到的端到端样貌

把上面串起来，这就是你的 AI 助手需要调 OpenAI 时跑的东西。你可以直接把这段 prompt 丢给它，
剩下它从 `schema` 自己读：

> 用 `akey` 调一下 OpenAI 的 models 接口。金库名是 `default`。不要 `akey read` 任何东西。

agent 会做这些事：

```bash
akey whoami --json                       # 自检：是不是在一台已配置的机器上
akey schema --json | jq '.commands[] | .name'   # 权威命令清单
akey list --json                         # 有哪些条目
akey get openai --json | \
  jq -r '.data.fields[] | select(.concealed) | .reference'
# → akey://default/openai/credential
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models
```

agent 永远看不到 key。它跑的子进程回显了任何东西，输出里都是 `<concealed by akey>`——而这正是
你想要的：agent **注意得到**的泄漏，就是已经**被卸掉**的泄漏。

---

## 第 9 步 —— 笔记本丢了

在仍然能用的那台机器上：

```bash
akey devices rm macbook
akey sync
```

这把 `vault.age` **重新加密**，不再把被盗那台的公钥放进取件人集合，并推上去。小偷拿到的
`identity.key` 与仓库里的任何东西都对不上。**你不必轮换笔记本曾经碰过的每一把 key**——
只轮换你担心真在它上面的那些。

如果那台笔记本当初没设 `--recovery`，另一个后果是**你**也没法在新机器上自举。今天没设的话，
去设一下。

---

## 第 10 步 —— 生成、审计，以及 `password` 分类

### 不入库的随机生成

```bash
akey generate                              # letters,digits,symbols,32
akey generate no-ambiguous,24              # 去掉 0/O/1/l/I/| — 读起来不容易混
akey generate hex,40                       # 40 个十六进制字符
akey generate passphrase,5                 # 5 个 EFF diceware 词，用 `-` 连接
akey generate --json letters,16            # {"ok":true,"data":{"password":"…"}}
```

配方 token：

| Token          | 含义 |
|---|---|
| `letters`, `digits`, `symbols` | 三种字符集（同时列出则取并集） |
| `no-ambiguous` | 从已有池里去掉 `0 O 1 l I |` |
| `hex`, `base32`, `base64`     | 用对应字母表替换整个池 |
| `passphrase`  | EFF 短词表；长度指的是**词数**，默认 5 |
| `<n>`         | 显式长度（字符 1..=4096；词 1..=10） |

`passphrase` 与字符集 token **互斥**——同时用是 usage 错误（退出 2）。生成完全本地，不碰网络、
不碰审计、连金库都不读。

### 审计

```bash
akey audit                                 # 人类可读
akey audit --json                          # 按问题分组
akey doctor --json                         # 同样的检查项，机器可读，带严重度
```

`audit` 与 `doctor` 一共覆盖四类问题：

- **弱密码（weak）** —— 长度 < 8、只有一种字符集、或命中内置的 top-1000 常见清单。
- **重复使用（reused）** —— 两条目存了同一个值。
- **陈旧轮换（stale）** —— `apikey` / `token` 类条目的 `rotated_at` 超过一年没动。
- **即将过期（expiring）** —— `expires_at` 在 30 天内（v0.3 之前已存在）。

输出**永远不含值，也不含值的哈希**——只有条目名、字段 id 和原因。`tests::audit_check_never_includes_value_or_hash` 把这条契约钉死。

### `password` 一等分类

「一条单独密码」—— WiFi PSK、不想归到 `database` 的数据库 root 密码、没有 username / URL 的
应用专属密钥——用新的 `password` 分类：

```bash
akey set wifi-home --category password --title "Home WiFi" --generate-password=no-ambiguous,24
akey get wifi-home --json | jq -r '.data.fields[0].reference'
# → akey://default/wifi-home/password
akey run --with WIFI_PSK=akey://wifi-home/password -- …         # 注入而不见值
```

只有一个字段（`password`，concealed），没有 `username`，没有 `url`。形状就是你想存的形状——
不被分类骨架牵着走。

### 收紧恢复密码

默认最小长度是 12。如果你的安全策略要求 16 或 20：

```bash
akey recovery rotate --min-passphrase-len 20        # 新密码至少 20 字符
akey recovery status --json                          # configured / min / current length / strength
```

`recovery status` 输出**长度**和一个粗的强度等级——从不输出密码本身。

---

```bash
# 发现
akey schema --json                    # 权威命令面
akey whoami --json                    # 设备、仓库、条目数、公钥
akey doctor --json                    # 权限位 / 远端 / 令牌 / 审计 / 冲突 检查
akey list --json                      # 条目（只有元数据）
akey audit --json                     # 弱 / 重复 / 陈旧 / 即将过期（不含值）
akey get <name> --json                # 单个条目（元数据 + 引用）

# 生成
akey generate                         # letters,digits,symbols,32
akey generate <recipe>                # 语法见第 10 步

# 编辑
printf 'credential=…\n' | akey set <name> --category <K> --stdin
akey edit <name> --title … --tags … --favorite --rotate --reveal-policy deny
akey mv <old> <new>                   # 改名；ID 稳定，引用继续生效
akey rm <name>                        # 软删（可 restore）
akey rm <name> --purge                # 硬删（不可恢复）
akey restore <name>
akey doc put <name> <file> --field <f> # 附件（kubeconfig、SA json）
akey doc get akey://<name>/<f> -o <file>

# 同步与设备
akey sync --json
akey devices list
akey devices trust <name>             # 在每台已有机器上各跑一次
akey recovery set | rotate | unlock

# 交付（给 agent）
akey run --with VAR=akey://item/field -- <cmd>
akey run --env-file .env -- <cmd>
akey run --bundle <env-bundle-name> -- <cmd>
akey inject -i config.yml.tpl -o config.yml
akey mcp                              # JSON-RPC over stdio；只出元数据

# CI
akey token create --name … --allow … --deny-reveal --ttl 30d
AKEY_TOKEN=akey_… akey run --with … -- <cmd>
akey token list
akey token rm <name>
```

## 绝对不能做的事

这些不是风格建议；它们会破坏安全模型：

| 禁止 | 为什么 | 换成 |
|---|---|---|
| `akey read <ref>` / `akey get --reveal` | 明文进你的上下文，收不回来 | `akey run --with … -- <命令>` |
| `akey export …` | 整库明文落盘 | 只注入你需要的 |
| `akey set x credential=sk-…`（值在 argv 里） | 进 shell 历史与 `ps` | `printf 'credential=…\n' \| akey set x --stdin` |
| 把 `AKEY_TOKEN` 打印出来 | 它是凭据 | 只放在环境变量里 |
| 收到 7 / 8 之后想办法绕过 | 那是策略，不是障碍 | 换路径或问人 |
| 直接编辑金库仓库里的文件 | 里面是密文，你会把它弄坏 | 一律走 CLI |
| 把 `identity.key` 拷到别的机器 | 设备吊销就失效了，且扩大暴露面 | `akey init --from <url>` + 恢复密码 |

## 什么时候必须停下来找人类

只有这四种：

1. `whoami` 退出 **4**，尤其 `doctor` 报 `this_device_is_recipient: error` —— 重新引导要恢复密码。
2. `token_scope`（退出 8）挡住了你真正需要的条目 —— 加宽权限是人做的决定。
3. 冲突里你判断不了哪一版是对的 —— 猜错会把生产密钥换成废的。
4. 你要先 `rm --purge` 或 `export` —— 两者都不可逆或突破边界。

其余情况你都应该能靠 `schema` + 退出码 + `list` 自己解决。