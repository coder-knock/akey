# Integrating `akey`: a guide for AI agents

> Written for **agents that use akey**, not for people maintaining it.
> By the end you should be able to pick your own commands, choose a channel to integrate through,
> recover from failures unaided, and know what you must never do.

> 中文版：[AGENT-INTEGRATION.zh-CN.md](AGENT-INTEGRATION.zh-CN.md)

---

## 0. Three laws

1. **Never fetch plaintext.** When you need a credential, wrap the command that needs it with
   `akey run`. `read` / `get --reveal` / `export` are human escape hatches — the moment you run
   one, the plaintext is in your context and cannot be recalled. Preventing exactly that is the
   entire reason this vault exists.
2. **Never memorise the command surface.** Run `akey schema --json` for the authoritative list
   and `akey list --json` to see what is available. If this document ever contradicts `schema`,
   `schema` wins.
3. **Never ask a human before reading the exit code.** Every failure carries a stable,
   machine-readable `error.code`, and §5 maps each one to your next action. Only the four
   situations in §10 justify stopping.

---

## 1. Thirty-second self-check: can I use this?

```bash
akey whoami --json           # which device am I, where is the repo, how many entries exist
akey doctor --json           # anything wrong? (permissions, remote, conflicts, expired tokens)
akey log --since 1h --json   # what has this machine read or written recently (never values)
```

`whoami` exiting **4** means this machine was never initialised. If you cannot even reach
`$HOME`, nobody has set it up for you — **stop and ask** (§10).

Every element of `doctor`'s `data.checks[]` carries `status: ok|warning|error`. An `error` means
do not proceed.

---

## 2. The only correct pose: inject, never fetch

```bash
akey run --with <VAR>=<reference> -- <command> [args...]
```

Four forms of `--with`:

| Form | Meaning |
|---|---|
| `OPENAI_API_KEY=akey://openai/credential` | Explicit reference (**preferred** — no ambiguity) |
| `OPENAI_API_KEY=openai` | Reference an entry by name: takes its default secret field |
| `openai` | Variable name derived from the entry name (`my.api` → `MY_API`) |
| `DB_URL=akey://db/host` | Reference any field, not only secret ones |

Two bulk entry points:

```bash
# A .env holding references instead of plaintext, injected as the whole environment
akey run --env-file .env -- node app.js

# Inject every field of an env-bundle entry
akey run --bundle prod-env -- ./deploy.sh
```

**Precedence** (high → low): `--with` > `--bundle` > `--env-file` (later files override earlier)
> your current process environment. Results are sorted by variable name, so identical inputs
> always produce identical injections — which is what makes this testable.

### Masking is on by default

Any secret the child process writes to stdout/stderr is replaced with `<concealed by akey>` —
even if it runs `printenv`. This exists to stop *you* from seeing plaintext by accident.
`--no-masking` turns it off, but **only use it for interactive child processes** (it also gives up
the pipes and keeps the TTY).

### Two exceptions for `run`

- **It emits no `--json` envelope.** stdout belongs to the child; passing `--json` changes nothing.
- **It passes the child's exit code straight through.** `akey run -- sh -c 'exit 42'` gives you 42.
  Do not treat every non-zero as "akey failed" — check whether the wrapped command is reporting
  the failure itself.

`akey mcp` behaves the same way: its stdout is a JSON-RPC stream (see §6.1).

---

## 2.5 Language

Every command accepts a global `--lang <tag>` (or `$AKEY_LANG`). It changes **human-readable
text only**: `--json` is byte-identical in every language, so parse `error.code` and the stable
keys, never the prose around them.

The one exception is `akey schema`, whose `summary` and `args[].help` fields *are* the `--help`
strings and so follow `--lang`. Every other payload — `list`, `get`, `doctor`, `whoami`,
`devices list`, and the rest — is stable. If you cache or diff `schema` output, pin
`--lang en` first.

If you match on human text for any reason, pin the language — `akey --lang en …` — so a user's
locale cannot change what you are matching. Supported tags are `en` and `zh-CN`; anything else is
refused with exit 2 when you asked for it explicitly by name.

## 3. Discovering capability: do not guess

```bash
akey schema --json           # every command, argument, global flag, env var, exit code, the reference grammar
akey list --json             # what is available right now (metadata only, never values)
akey template list --json    # which categories exist, their field skeletons and default secret field
akey get <entry> --json      # the shape of one entry: field names, types, and each field's reference
```

Every field in `get`'s output carries a `reference`:

```json
{ "id": "credential", "type": "concealed", "concealed": true,
  "value": "********", "reference": "akey://default/openai/credential" }
```

**Treat the `reference` as the thing you wanted.** It is exactly the string you feed to
`run` / `inject`. You do not know the value and you do not need it.

---

## 4. Reference grammar at a glance

```
akey://[<vault>/]<item>[/<section>]/<field>[?attribute=...]
```

- The item may be a **name or a 26-character ID**. IDs survive renames, so use IDs in long-lived scripts.
- Case-insensitive; each segment allows alphanumerics plus `-` `_` `.` (**no spaces**).
- `$VAR` is expanded: `akey://$APP_ENV/db/password` (variables come from your process environment).
- Query parameters:
  - `?attribute=otp` — when the field holds an `otpauth://…` value, compute the 6-digit code (for 2FA)
  - `?attribute=title|type|id` — return metadata instead of the value (non-secret, safe in context)

```bash
akey run --with OTP=akey://github/one-time-password?attribute=otp -- ./login.sh
```

---

## 5. Exit code → what you do next

On failure **stdout is empty**, and the error envelope goes to **stderr**:
`{"ok":false,"error":{"code":"…","message":"…","hint":"…"}}`

| code | exit | Meaning | What you do |
|---|---|---|---|
| `usage` | 2 | Bad arguments | Check `akey schema --json`; do not retry the same call |
| `not_found` | 3 | No such entry/field | Run `akey list --json` to see the real names |
| `ambiguous` | 3 | Name is not unique | Use the entry ID (it is in `akey list --json`) |
| `locked` | 4 | No identity / cannot decrypt / bad token | This machine is not set up. **Stop and ask** (§10) |
| `conflict` | 5 | Sync produced conflict copies | Run `akey conflicts --json` — see §9.1 |
| `sync_failed` | 6 | git or remote problem | Retry once with backoff; if it persists, ask |
| `denied` | 7 | Policy forbids this | **Do not route around it.** Use `run` to inject; writes need the local identity |
| `token_scope` | 8 | Your token does not cover this entry | Use another entry, or ask for a wider `--allow`. **Do not attempt to bypass** |
| `io`/`crypto`/`corrupt`/`git`/`unsupported` | 1 | Internal error | Run `akey doctor --json` and hand the output to a human |

**One important exception**: with `run`, the exit code comes from the wrapped command, not this table.

---

## 6. Wiring akey into your toolchain

### 6.1 MCP (least effort)

`akey mcp` is a stdio JSON-RPC 2.0 server using **newline-delimited** messages (not LSP's
Content-Length framing). It exposes metadata only and **never returns a value** — the design
closes the "agent obtains plaintext" path by construction.

```jsonc
// mcp.json
{ "mcpServers": {
    "akey": { "command": "akey", "args": ["mcp"] }
} }
```

It offers `akey_list` (the inventory) and `akey_get` (field names, types and references for one
entry). To actually use a secret, still go through `akey run` (§6.2) — MCP answers "what is there",
`run` answers "use it".

### 6.2 Wrapping a child process (universal)

```bash
# One step
akey run --with OPENAI_API_KEY=akey://openai/credential -- python summarize.py

# Several entries, several variables
akey run \
  --with OPENAI_API_KEY=akey://openai/credential \
  --with DB_PASSWORD=akey://db/password \
  --env-file .env \
  -- ./run-everything.sh
```

Advice for your host program: make `akey run` the **single** door to secrets in your tool
definitions, and never expose `akey read`.

### 6.3 Unattended / CI: use a capability token, not a device identity

```bash
# Run once by a human, holding the device identity:
akey token create --name ci-narrow --allow openai,anthropic --deny-reveal --ttl 30d
# Shown exactly once — record it for CI
```

Then in CI:

```bash
export AKEY_TOKEN=akey_...
akey run --with OPENAI_API_KEY=akey://openai/credential -- ./build.sh
```

The token's constraints are all hard:

- Entries outside `--allow`: exit **8**, for both injection and reading.
- `--deny-reveal`: any plaintext fetch → exit **7**.
- **A token is a read-only credential**: `set`/`edit`/`rm`/`restore`/`cp`/`mv`/`resolve`/`import`/`doc put`
  all return **7**.
- `export` emits only the entries inside the scope.
- It expires at `--ttl`; `akey token rm <name>` revokes it immediately.

**Corollary**: if you hold an `AKEY_TOKEN`, do not attempt writes or out-of-scope entries.
They cannot succeed by design, and the failure codes will cost you turns.

### 6.4 Config templates (secrets stay out of version control)

```bash
akey inject -i config.yml.tpl -o config.yml
```

The template uses references instead of plaintext, so it is safe to commit:

```yaml
database:
  username: akey://db/username
  password: akey://db/password
```

### 6.5 Project `.env` holding references

```bash
# .env — safe to commit
OPENAI_API_KEY=akey://openai/credential
DB_PASSWORD=akey://db/password
```

```bash
akey run --env-file .env -- npm start
```

**Note**: `${VAR}` in the *same* command line is expanded by the shell before `akey` sees it, so use
`akey run --env-file .env -- sh -c 'echo $DB_PASSWORD'`; writing `echo $DB_PASSWORD` directly
yields an empty string.

---

## 7. Recipes

```bash
# HTTP / REST
akey run --with TOKEN=akey://tavily/credential -- \
  curl -sS -H "Authorization: Bearer $TOKEN" https://api.tavily.com/search -d '{"query":"…"}'

# Node
akey run --env-file .env -- node -e 'console.log(process.env.OPENAI_API_KEY ? "ok" : "missing")'

# Docker
akey run --with DOCKER_PASSWORD=akey://registry/password -- \
  sh -c 'echo "$DOCKER_PASSWORD" | docker login -u ci --password-stdin'

# gh / git (the token lives only in the child's environment)
akey run --with GH_TOKEN=akey://github/credential -- gh pr list

# Database migrations
akey run --with DATABASE_URL=akey://db/url -- ./migrate up

# 2FA codes
akey run --with OTP=akey://github/one-time-password?attribute=otp -- ./totp-login.sh

# Reading non-secret metadata (safe to put in context)
akey get openai --json | jq -r '.data.fields[] | .reference'   # the reference string, not the value
```

**Rotating a key** (needs the local device identity, not a token):

```bash
printf 'credential=sk-new-value\n' | akey set openai --stdin
akey sync            # push; other devices pick it up on their next sync
```

### 7.6 Maintenance (needs the local device identity — **a token cannot do this**)

Everything below mutates the vault. Holding `AKEY_TOKEN`, each of these returns exit code **7**.
That is the design, not a fault. They are available only under the local device identity.

```bash
# Create / update. Secrets go over stdin, never into argv.
printf 'credential=sk-new\n' | akey set openai --category apikey --stdin
akey set db --category database host=db.internal port=5432 username=app

# Metadata only (values untouched): title, tags, favourite
akey edit openai --title "OpenAI prod" --tags llm,prod --favorite

# After rotating, refresh rotated_at so `list` can tell when it last changed
printf 'credential=sk-rotated\n' | akey set openai --stdin && akey edit openai --rotate

# Tighten: stop this entry's plaintext from ever being fetched (injection is unaffected)
akey edit openai --reveal-policy deny

# Rename (the ID is stable, existing references keep working) and copy
akey mv openai openai-prod
akey cp openai openai-staging

# Delete: soft by default (restorable); --purge removes it for good
akey rm openai-staging
akey restore openai-staging
akey rm openai-staging --purge

# File attachments: kubeconfigs, service-account JSON, and the like — byte-exact round trip
akey doc put k8s-prod ./kubeconfig --field kubeconfig
akey doc get akey://k8s-prod/kubeconfig -o ./kubeconfig

# Migrate in from another vault (duplicate names are refused; --merge overwrites matching fields)
akey import --as json -i dump.json --merge

# Approve a new device. Run this on **every existing machine** before that device
# can read what the machine writes.
akey devices trust laptop
```

Assignment syntax is `[<section>.]<field>[[<type>]]=<value>`, e.g. `akey set api 'creds.token[concealed]=abc'`.
**A value in argv triggers a warning** — it lands in your shell history and `ps` output.
Always send secrets through `--stdin`.

`akey completion <shell>` emits a shell completion script for humans; it is not for you.

---

## 8. Forbidden

These are not style advice; they break the security model.

| Never | Why | Do this instead |
|---|---|---|
| `akey read …` / `akey get --reveal` | Plaintext enters your context irreversibly | `akey run --with … -- <command>` |
| `akey export …` | Dumps the whole vault to disk in the clear | Inject only what you need |
| Putting a secret in your prompt / memory / output | Permanent disclosure | Refer to it: `akey://openai/credential` |
| Passing a secret in argv (`akey set x credential=sk-…`) | Lands in shell history and `ps` | `printf 'credential=…\n' \| akey set x --stdin` |
| Printing `AKEY_TOKEN` | It is a credential | Keep it in the environment |
| Working around exit 7 / 8 | Those are policy, not obstacles | Change path, or ask (§10) |
| Editing files inside the vault repository directly | It is ciphertext; you will corrupt it | Always go through the CLI |
| Copying `identity.key` to another machine | Device revocation stops working, and you widen exposure | `akey init --from <url>` + recovery passphrase |

---

## 9. Recovering from failure

### 9.1 Sync conflict (exit 5)

Two devices changed the same entry. **Nothing was lost** — the merge already completed and pushed;
`ours` kept the original name and `theirs` became `<name>.conflict.<short-id>`. Exit code 5 means
"a human needs to pick a side".

```bash
akey conflicts --json           # list them, in pairs
akey resolve <name> --ours      # keep the local version
akey resolve <name> --theirs    # adopt the remote version
akey sync                       # re-push after converging
```

**Which side?** If you just changed that entry, take `--ours`. If the remote looks newer (a human
rotated the key, say), take `--theirs`. If you cannot tell, ask (§10) — a wrong key costs more than
a pause.

### 9.2 Exit 4 saying "this device was revoked"

`akey doctor --json` will show `this_device_is_recipient: error`. This machine was removed from the
recipients by `akey devices rm`; it can no longer decrypt new revisions, **and that is irreversible** —
the old identity is never re-admitted.

Stop and ask. The usual fix is: on a still-valid device run `akey recovery set` (or confirm the
recovery passphrase works), then re-bootstrap this machine.

### 9.3 Exit 8 / 7

Not malfunctions — policy. Use another entry or another path; for wider access, have a human run
`akey token create --allow <the entries you need>`.

### 9.4 Exit 6

The remote is unreachable or its credentials are wrong. `akey sync --status --json` shows how far
ahead/behind you are. Retry once with backoff; if it still fails, hand `akey doctor --json`'s output
to a human.

---

## 10. When you must stop and find a human

Only these four:

1. **Exit 4**, especially when `doctor` reports this device is not a recipient — re-bootstrapping
   involves the recovery passphrase.
2. **`token_scope` blocks an entry you genuinely need** — widening access is a human decision.
3. **You cannot tell which side of a conflict is correct** — guessing swaps a production key for a dead one.
4. **You are about to delete data** (`rm --purge`) or **export plaintext** (`export`) — both are
   irreversible or cross a boundary.

Everything else you should be able to resolve yourself from `schema`, the exit code, and `list`.

---

## 11. A complete example, start to finish

```bash
# Learn the environment
akey whoami --json
akey list --json

# Find the entry you want and its reference
akey get openai --json | jq -r '.data.fields[] | select(.concealed) | .reference'
# → akey://default/openai/credential

# Use it, never touching the plaintext
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models

# If this machine is behind the others
akey sync --json
```

---

## Appendix: every environment variable mentioned here

| | Purpose |
|---|---|
| `AKEY_HOME` | Override the local private directory (default `~/.config/akey`) |
| `AKEY_TOKEN` | Capability token; equivalent to `--token` |
| `AKEY_NO_REVEAL` | Set to anything non-empty to **ban all plaintext fetching globally** |
| `AKEY_DEVICE_NAME` | Default device name for `init` |
| `AKEY_RECOVERY_PASSPHRASE` | Non-interactive recovery passphrase (bootstrap, `recovery unlock`, the old one for `rotate`) |
| `AKEY_NEW_RECOVERY_PASSPHRASE` | The new passphrase for `recovery rotate` |

For authoritative, complete information: `akey schema --json`.

## 12. Limits you should not design around

- **Masking is a guardrail, not a sandbox.** `akey run` hides secrets the child *accidentally*
  prints. A child that means to exfiltrate already has the value in its environment; it can base64
  it, split it across stdout and stderr, or write it to a socket. Do not treat `akey run` as a
  confidentiality boundary against hostile code.
- **The remote cannot decide who can read.** `recipients.json` is distributed by the git remote, so
  a key pushed into it is *listed* but never encrypted to — encryption goes only to keys this
  machine approved locally. A device joining from elsewhere therefore needs a human on each existing
  machine to run `akey devices trust <name>` before it can read what that machine writes. `akey sync`
  and `akey doctor` report unapproved keys as pending. Details: `docs/SECURITY.md` §5.
- **A token is a policy check, not a separate identity.** Anyone who can run `akey` on a device can
  read `identity.key`. Use tokens to limit what *an agent's normal commands* touch — not as a
  cryptographic boundary.
- **TOTP codes are meant to be shown.** `akey://…?attribute=otp` returns the 6-digit code, not the
  seed. The seed itself is concealed like any other secret.

The full threat model, the attack simulations and every finding are in `docs/SECURITY.md`.
