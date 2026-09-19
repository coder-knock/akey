---
name: akey
description: >-
  Use an `akey` encrypted credential vault to obtain API keys, tokens, passwords and TOTP codes
  without ever putting the plaintext into context. Trigger when a task needs a credential the
  environment does not already hold — calling a paid API, authenticating a CLI, logging into a
  registry or database, reading a project `.env` that contains `akey://` references, wiring an MCP
  server that needs secrets, or syncing/rotating secrets across machines. Also trigger on
  "akey", "credential vault", "get an API key", "I need a token", "where are the secrets",
  "sync secrets". Do NOT trigger to store, reveal, or export a secret the user just pasted into the
  chat — explain why and route them to `akey set --stdin` instead.
---

# akey

Hand the secret to the **process that needs it**, not to **you**.

## Self-check first

```bash
akey whoami --json     # exit 4 = this machine was never set up → stop and ask a human
akey doctor --json     # any check with status "error" means do not proceed
akey schema --json     # the authoritative command list (if this skill disagrees, schema wins)
```

## The core pose

When you need a credential, **wrap the command**. Do not fetch the value:

```bash
akey run --with OPENAI_API_KEY=akey://openai/credential -- <command> [args...]
```

- `--with VAR=akey://item/field` — explicit reference (preferred)
- `--with VAR=item` — take that entry's default secret field
- `--with item` — variable name derived from the entry name (`my.api` → `MY_API`)
- `--env-file .env -- <command>` — inject a whole dotenv (with `akey://` references inside)
- `--bundle <item> -- <command>` — inject every field of an `env-bundle` entry

Anything the child prints that looks like a secret is replaced with `<concealed by akey>`.
`akey run`'s stdout belongs to the child, and **so does the exit code** — do not read it as an
akey failure.

## Language

Add `--lang en` if you parse any human-readable text; `--json` output is identical in every
language, so prefer that. Supported: `en`, `zh-CN`. Exception: `schema --json` carries the
`--help` strings and does follow `--lang`.

## Finding the reference string

```bash
akey list --json                                     # what exists (metadata only)
akey get <item> --json | jq -r '.data.fields[] | .reference'
# → akey://default/openai/credential        ← this is what you pass to --with
```

A reference is `akey://[vault/]item[/section]/field`. The item may be a name or an ID
(use IDs in scripts — they survive renames). `?attribute=otp` computes a 6-digit code;
`?attribute=title|type|id` returns non-secret metadata. There are no spaces in segments.

## Exit code → next action

| Code | Meaning | Do this |
|---|---|---|
| 2 | Bad arguments | Fix against `akey schema --json`; do not retry the same call |
| 3 | Not found / ambiguous | `akey list --json` for real names; use the ID if ambiguous |
| 4 | No identity, or revoked | **Stop and ask a human** |
| 5 | Sync conflict | `akey conflicts --json` → `akey resolve <name> --ours\|--theirs` → `akey sync` |
| 6 | git/remote broken | Retry once with backoff, then ask |
| 7 | Policy denied | Use `run` to inject instead. **Do not work around it** |
| 8 | Token out of scope | Another entry, or ask for a wider `--allow`. **Do not work around it** |

stdout carries data only; the error envelope goes to stderr:
`{"ok":false,"error":{"code":…,"hint":…}}`.

## Masking has a floor

`run` replaces any secret the child prints with `<concealed by akey>` — but only values of **8
characters or more**. Shorter ones are left alone on purpose, so ordinary output is not turned into
mosaic. A short secret is therefore not concealed; treat it as if it were printed in the clear.

## Never

- `akey read` / `get --reveal` / `export` → plaintext in your context, unrecoverable. Inject instead.
- Writing a secret into your prompt, memory, or output. Refer to it as `akey://…`.
- Passing a secret in argv → `printf 'credential=…\n' | akey set <name> --stdin`.
- Working around exit 7 / 8 → those are policy, not obstacles.
- Editing files in the vault repository directly → it is ciphertext.

## When you hold an `AKEY_TOKEN`

It is a **read-only** credential: `set/edit/rm/restore/cp/mv/resolve/import/doc put` all exit 7;
entries outside `--allow` exit 8 for reading *and* injection; `--deny-reveal` denies every
plaintext fetch. Do not try — these cannot succeed by design.

## MCP

```jsonc
{ "mcpServers": { "akey": { "command": "akey", "args": ["mcp"] } } }
```

stdio, newline-delimited JSON-RPC 2.0; only `akey_list` and `akey_get`, and it **never returns a
value**. It answers "what is there"; `akey run` answers "use it".

## Working with other devices

```bash
akey sync --json     # exit 5 = conflicts await resolution (the merge and push already succeeded; nothing was lost)
```

`sync` reports any recipient that appears in the repository without this machine's approval. Those
keys receive **no ciphertext**. If a device you actually added shows up as pending, approve it with
`akey devices trust <name>` — a human has to do that on each existing machine.

## Full version

`docs/AGENT-INTEGRATION.md` — recipes (curl / node / docker / gh / databases / 2FA), CI setup,
template injection, self-healing flows, and exactly when to stop and ask a human.
