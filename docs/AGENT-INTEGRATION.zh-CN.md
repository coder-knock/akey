# 接入 `akey`：给 AI agent 的指南

> 读者是**要使用 akey 的 agent**，不是维护 akey 的人。
> 目标：读完你能自己决定用什么命令、接进哪个通道、出错怎么自愈、以及哪些事绝对不能做。

---

## 0. 三条铁律

1. **不要取明文。** 需要密钥去做什么，就用 `akey run` 把密钥注入那个进程。
   `read` / `get --reveal` / `export` 是给人用的逃生口——你一旦执行，明文就进了你的上下文，
   收不回来了，而这个库存在的全部意义就是不让它发生。
2. **不要背命令。** 跑 `akey schema --json` 拿权威清单，跑 `akey list --json` 看有什么可用。
   本文件若与 `schema` 冲突，以 `schema` 为准。
3. **不要问人，先读退出码。** 所有失败都有稳定的机器可读 `error.code`，
   §5 给了每个码对应的下一步。只有 §10 列出的四种情况才需要停下来找人类。

---

## 1. 三十秒自检：我能不能用 akey

```bash
akey whoami --json     # 我是哪台设备、仓库在哪、库里有多少条目
akey doctor --json     # 有没有问题（权限位、远端、冲突、令牌过期）
akey log --since 1h --json   # 这台机器最近读过/写过什么（不含值）
```

`whoami` 退出 4 = 这台机器还没初始化。你若无法访问 `$HOME`，说明没人给你配过，此时**停下来问人**（§10）。

`doctor` 的 `data.checks[]` 每项有 `status: ok|warning|error`。有 `error` 就别往下走。

---

## 2. 唯一正确的用法：注入，不取值

```bash
akey run --with <变量名>=<引用> -- <命令> [参数...]
```

`--with` 的四种写法：

| 写法 | 含义 |
|---|---|
| `OPENAI_API_KEY=akey://openai/credential` | 显式引用（**推荐**，无歧义） |
| `OPENAI_API_KEY=openai` | 引用某个条目：取该条目的默认秘密字段 |
| `openai` | 变量名由条目名派生（`my.api` → `MY_API`） |
| `DB_URL=akey://db/host` | 引用任意字段，不只秘密字段 |

还有两个批量入口：

```bash
# .env 里写引用而不是明文，整个文件作为环境注入
akey run --env-file .env -- node app.js

# 把某条 env-bundle 条目的全部字段都注入
akey run --bundle prod-env -- ./deploy.sh
```

**优先级**（高 → 低）：`--with` > `--bundle` > `--env-file`（多文件时后者覆盖前者）> 你当前进程的环境。
结果按变量名排序，所以同样的输入永远得到同样的注入，可测。

### 遮蔽是默认开的

子进程往 stdout/stderr 打的任何密钥都会被换成 `<concealed by akey>`——哪怕它 `printenv`。
这是防止你"一不小心"看见明文。`--no-masking` 关掉它，但**只在你需要交互式子进程时用**
（它会同时放弃管道、保留 TTY）。

### `run` 的两个特例

- **它不输出 `--json` 信封**：stdout 属于子进程，加了 `--json` 也不改变这一点。
- **它透传子进程的退出码**。你跑 `akey run -- sh -c 'exit 42'`，得到的就是 42。
  别把非零一律当成"akey 出错了"——先看是不是被包装的命令自己在报错。

同理的还有 `akey mcp`（见 §6.1），它的 stdout 是 JSON-RPC 流。

---

## 3. 发现能力：别猜

```bash
akey schema --json      # 全部命令、参数、全局标志、环境变量、退出码、引用语法
akey list --json        # 当前可用条目（只有元数据，永不含值）
akey template list --json   # 有哪些分类，各自的字段骨架与默认秘密字段
akey get <条目> --json  # 一个条目的形状：字段名、类型、以及每个字段的 reference
```

`get` 的输出里每个字段都带 `reference`：

```json
{ "id": "credential", "type": "concealed", "concealed": true,
  "value": "********", "reference": "akey://default/openai/credential" }
```

**把 `reference` 当作你要用的东西**——它就是你该喂给 `run` / `inject` 的字符串。
你不用知道值，也不需要值。

---

## 4. 引用语法速查

```
akey://[<vault>/]<条目>[/<section>]/<字段>[?attribute=...]
```

- 条目可用**名字或 26 位 ID**。ID 在改名后依然有效，所以长期脚本请用 ID。
- 大小写不敏感；段内只允许字母数字与 `-` `_` `.`（**不允许空格**）。
- `$VAR` 会展开：`akey://$APP_ENV/db/password`（变量取自你当前进程的环境）。
- 查询参数：
  - `?attribute=otp` —— 字段值形如 `otpauth://…` 时现算 6 位动态口令（做 2FA 用）
  - `?attribute=title|type|id` —— 取元数据而非值（非秘密，可安全放进上下文）

```bash
akey run --with OTP=akey://github/one-time-password?attribute=otp -- ./login.sh
```

---

## 5. 退出码 → 你下一步做什么

失败时 **stdout 是空的**，错误信封在 **stderr**：
`{"ok":false,"error":{"code":"…","message":"…","hint":"…"}}`

| code | 退出码 | 含义 | 你该做什么 |
|---|---|---|---|
| `usage` | 2 | 参数不对 | 跑 `akey schema --json` 对着改；别重试同样参数 |
| `not_found` | 3 | 条目/字段不存在 | 跑 `akey list --json` 看真实的条目名 |
| `ambiguous` | 3 | 名字不唯一 | 改用条目 ID（`akey list --json` 里有 `id`） |
| `locked` | 4 | 没身份 / 解不开 / 令牌无效 | 这台机器没配好。**停下来问人**（§10） |
| `conflict` | 5 | 同步产生冲突副本 | 跑 `akey conflicts --json`，见 §9.1 |
| `sync_failed` | 6 | git/远端问题 | 网络或远端坏了。可以退避后重试一次；再不行问人 |
| `denied` | 7 | 策略禁止这么做 | **不要绕过**。改走 `run` 注入；写操作需要本机身份 |
| `token_scope` | 8 | 你的令牌管不到这个条目 | 换个条目，或请人加宽 `--allow`。**不要尝试绕过** |
| `io`/`crypto`/`corrupt`/`git`/`unsupported` | 1 | 内部错误 | 跑 `akey doctor --json`，把输出交给人类 |

**一个重要的例外**：`run` 的退出码来自被包装的命令，不是上表。

---

## 6. 把 akey 接进你的工具链

### 6.1 MCP（最省事）

`akey mcp` 是一个 stdio JSON-RPC 2.0 服务，**换行分隔**（不是 LSP 的 Content-Length 帧）。
它只暴露元数据，**永不返回值**——设计上就堵死了"agent 拿到明文"这条路。

```jsonc
// mcp.json
{ "mcpServers": {
    "akey": { "command": "akey", "args": ["mcp"] }
} }
```

它提供 `akey_list`（条目清单）与 `akey_get`（某条目的字段名/类型/reference）。
要真用密钥，仍然走 `akey run`（§6.2）——MCP 负责"知道有什么"，`run` 负责"用起来"。

### 6.2 包装子进程（通用）

```bash
# 只要一步
akey run --with OPENAI_API_KEY=akey://openai/credential -- python summarize.py

# 需要多个条目、多个变量
akey run \
  --with OPENAI_API_KEY=akey://openai/credential \
  --with DB_PASSWORD=akey://db/password \
  --env-file .env \
  -- ./run-everything.sh
```

给你的宿主程序的建议：把 `akey run` 作为**唯一的密钥入口**写进工具定义，别暴露 `akey read`。

### 6.3 无人值守 / CI：用能力令牌，别用设备身份

```bash
# 由人类执行一次（需要本机设备身份）：
akey token create --name ci-narrow --allow openai,anthropic --deny-reveal --ttl 30d
# 只回显一次，记下来给 CI
```

之后 CI 里：

```bash
export AKEY_TOKEN=akey_...
akey run --with OPENAI_API_KEY=akey://openai/credential -- ./build.sh
```

令牌的约束（都是硬的）：

- `--allow` 之外的条目：退出码 **8**，注入和读取都挡。
- `--deny-reveal`：任何取明文 → 退出码 **7**。
- **令牌是只读凭据**：`set`/`edit`/`rm`/`restore`/`cp`/`mv`/`resolve`/`import`/`doc put` 一律 **7**。
- `export` 只导出作用域内的条目。
- 到 `--ttl` 自动失效；`akey token rm <名字>` 立即吊销。

**推论**：你要是拿着 `AKEY_TOKEN`，就别去试写操作或越权条目——那是设计上不可能成功的，
高退出码会浪费你的回合。

### 6.4 配置文件模板（密钥不进版本库）

```bash
akey inject -i config.yml.tpl -o config.yml
```

`config.yml.tpl` 里用引用代替明文，模板可以放心提交：

```yaml
database:
  username: akey://db/username
  password: akey://db/password
```

### 6.5 项目 `.env` 里写引用而非明文

```bash
# .env —— 可以安全提交
OPENAI_API_KEY=akey://openai/credential
DB_PASSWORD=akey://db/password
```

```bash
akey run --env-file .env -- npm start
```

**注意**：`${VAR}` 在本句同一命令行里会被 shell 先展开，所以
`akey run --env-file .env -- sh -c 'echo $DB_PASSWORD'` 才拿得到值；直接写 `echo $DB_PASSWORD` 拿到空串。

---

## 7. 常见配方

```bash
# HTTP / REST
akey run --with TOKEN=akey://tavily/credential -- \
  curl -sS -H "Authorization: Bearer $TOKEN" https://api.tavily.com/search -d '{"query":"…"}'

# Node
akey run --env-file .env -- node -e 'console.log(process.env.OPENAI_API_KEY ? "ok" : "missing")'

# Docker
akey run --with DOCKER_PASSWORD=akey://registry/password -- \
  sh -c 'echo "$DOCKER_PASSWORD" | docker login -u ci --password-stdin'

# gh / git（令牌只在子进程环境里）
akey run --with GH_TOKEN=akey://github/credential -- gh pr list

# 数据库迁移
akey run --with DATABASE_URL=akey://db/url -- ./migrate up

# 2FA 动态口令
akey run --with OTP=akey://github/one-time-password?attribute=otp -- ./totp-login.sh

# 读非秘密元数据（可以安全放进上下文）
akey get openai --json | jq -r '.data.fields[] | .reference'   # 拿到引用串，不是值
```

**轮换一个 key**（需要本机设备身份，不是令牌）：

```bash
printf 'credential=sk-new-value\n' | akey set openai --stdin
akey sync            # 推到远端，其他设备下次 sync 时拿到
```

---

### 7.6 维护条目（需要本机设备身份，**令牌做不到**）

下面这些会改库。拿着 `AKEY_TOKEN` 时它们一律返回退出码 **7**——那是设计，不是故障。
只有以本机设备身份运行时才用得上。

```bash
# 新建 / 更新。秘密走 stdin，别进 argv
printf 'credential=sk-new\n' | akey set openai --category apikey --stdin
akey set db --category database host=db.internal port=5432 username=app

# 改元数据（不动值）：标题、标签、收藏
akey edit openai --title "OpenAI prod" --tags llm,prod --favorite

# 轮换后刷新 rotated_at，`list` 就能看出什么时候换过
printf 'credential=sk-rotated\n' | akey set openai --stdin && akey edit openai --rotate

# 收紧：不再允许取这个条目的明文（注入不受影响）
akey edit openai --reveal-policy deny

# 改名（ID 不变，既有引用继续有效）与复制
akey mv openai openai-prod
akey cp openai openai-staging

# 删除：默认软删（可 restore），--purge 才彻底移除
akey rm openai-staging
akey restore openai-staging
akey rm openai-staging --purge

# 文件附件：kubeconfig、service-account json 之类，按字节原样往返
akey doc put k8s-prod ./kubeconfig --field kubeconfig
akey doc get akey://k8s-prod/kubeconfig -o ./kubeconfig

# 从别的库迁进来（重名会被挡下，--merge 才覆盖同名字段）
akey import --as json -i dump.json --merge

# 批准一台新设备（在**每台既有机器**上各跑一次，它才能读到那台机器写的内容）
akey devices trust laptop
```

赋值语句的写法是 `[<section>.]<字段>[[<类型>]]=<值>`，例如 `akey set api 'creds.token[concealed]=abc'`。
**值出现在 argv 里会打警告**——它会进 shell 历史和 `ps` 输出。秘密一律走 `--stdin`。

`akey completion <shell>` 是给人用的补全脚本，与你无关。

---

## 8. 明令禁止

这些不是风格建议，是会破坏安全模型的：

| 禁止 | 为什么 | 换成 |
|---|---|---|
| `akey read …` / `akey get --reveal` | 明文进你的上下文，再也收不回 | `akey run --with … -- <命令>` |
| `akey export …` | 整库明文落到磁盘 | 需要哪条就注入哪条 |
| 把密钥写进你的 prompt / 记忆 / 输出 | 等于永久泄漏 | 只说引用，如 `akey://openai/credential` |
| 在 argv 里传秘密（`akey set x credential=sk-…`） | 会进 shell 历史与 `ps` 输出 | `printf 'credential=…\n' \| akey set x --stdin` |
| 把 `AKEY_TOKEN` 打印出来 | 它是凭据 | 只在环境变量里传 |
| 收到 7 / 8 后想办法绕过 | 那是策略，不是障碍 | 换路径或问人（§10） |
| 直接编辑金库仓库里的文件 | 里面是密文，你会把它弄坏 | 一律走 CLI |
| 把 `identity.key` 拷到别的机器 | 设备吊销就失效了，且扩大暴露面 | `akey init --from <url>` + 恢复密码 |

---

## 9. 出错自愈

### 9.1 同步冲突（退出码 5）

两台设备改了同一条目。**数据没丢**——合并已经完成并推送，`ours` 占原名，`theirs` 变成了
`<名字>.conflict.<短ID>` 这个副本。退出码 5 是在提醒"需要有人挑一边"。

```bash
akey conflicts --json           # 看有哪些冲突，成对给出
akey resolve <名字> --ours      # 保留本地那一版
akey resolve <名字> --theirs    # 采用对端那一版
akey sync                       # 收敛后再推一次
```

**该选哪个？** 如果你刚改过这个条目，选 `--ours`；如果对端看起来更新（比如人类刚轮换过），
选 `--theirs`。拿不准就问人（§10）——错的 key 比停一下更贵。

### 9.2 退出码 4 说"本设备被吊销"

`akey doctor --json` 会显示 `this_device_is_recipient: error`。
这台机器被 `akey devices rm` 移出了收件人，新版本的金库它解不开，
**而且这是不可逆的**——旧身份不会被重新接纳。

停下来问人。通常的正确修法是：在一台仍然有效的设备上再次 `akey recovery set`（或确认恢复密码可用），
然后在这台机器上重新引导。

### 9.3 退出码 8 / 7

不是故障，是策略。换条目或换路径；需要更宽权限就请人执行
`akey token create --allow <你要的条目>`。

### 9.4 退出码 6

远端不可达或凭据问题。`akey sync --status --json` 能看出本地领先/落后多少。
退避重试一次；仍失败就把 `akey doctor --json` 的输出交给人类。

---

## 10. 什么情况下必须停下来找人类

只有这四种：

1. **退出码 4**，尤其 `doctor` 报本设备不是收件人 —— 需要重新引导，涉及恢复密码。
2. **`token_scope` 挡住了你真正需要的条目** —— 加宽权限是人做的决定。
3. **冲突里你无法判断哪一版是对的** —— 猜错会把生产密钥换成废的。
4. **要先删数据**（`rm --purge`）或**要导出明文**（`export`）—— 两者都不可逆或突破边界。

其余情况你都应该能靠 `schema` + 退出码 + `list` 自己解决。

---

## 11. 一个完整例子：从零到跑通

```bash
# 认识环境
akey whoami --json
akey list --json

# 发现我要的条目与它的引用
akey get openai --json | jq -r '.data.fields[] | select(.concealed) | .reference'
# → akey://default/openai/credential

# 用它，全程不接触明文
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models

# 如果这台机器落后于其他设备
akey sync --json
```

---

## 附：本文件里出现的所有环境变量

| | 作用 |
|---|---|
| `AKEY_HOME` | 覆盖本机私有目录（默认 `~/.config/akey`） |
| `AKEY_TOKEN` | 能力令牌；等价于 `--token` |
| `AKEY_NO_REVEAL` | 设为非空即**全局禁止取明文**（除了 `1` 之外的任意值都算开） |
| `AKEY_DEVICE_NAME` | `init` 时的默认设备名 |
| `AKEY_RECOVERY_PASSPHRASE` | 非交互提供恢复密码（引导、`recovery unlock`、`rotate` 的旧密码） |
| `AKEY_NEW_RECOVERY_PASSPHRASE` | `recovery rotate` 的新密码 |

需要更权威、更完整的信息：`akey schema --json`。

## 12. 你不该拿它当边界的几件事

- **掩蔽是护栏，不是沙箱。** `akey run` 挡的是子进程**误回显**。一个存心外泄的子进程本来就握着值：它base64 一下、拆到 stdout/stderr 两边、或写个 socket 都行。不要把 `akey run` 当成对抗恶意代码的机密性边界。
- **远端决定不了谁能读。** `recipients.json` 由 git 远端分发，所以被塞进去的公钥只会被**列出来**，永远不会被加密到——加密只给本机在本地批准过的公钥。因此从别处加入的设备，需要在**每台既有机器**上由人跑一次 `akey devices trust <名字>`，才能读到那台机器写的内容。未批准的公钥由 `akey sync` 与 `akey doctor` 报为 pending。细节见 `docs/SECURITY.zh-CN.md` §5。
- **令牌是策略检查，不是独立身份。** 能在这台机器上跑 `akey` 的人就能读 `identity.key`。令牌的作用是限制**某个 agent 的日常命令**能碰什么，不是密码学边界。
- **TOTP 动态码本来就该显示。** `akey://…?attribute=otp` 返回的是 6 位码，不是种子；种子与其它秘密一样默认隐藏。

完整威胁模型、攻防模拟与全部发现见 `docs/SECURITY.zh-CN.md`。
