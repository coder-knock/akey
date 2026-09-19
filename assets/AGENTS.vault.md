# This is an `akey` vault

Everything in this repository is **encrypted**. `vault.age` is an [age](https://age-encryption.org)
file readable only by the devices listed in `recipients.json`. `recipients.json` contains public
keys only. Do not try to read secrets out of these files by hand — use the `akey` CLI.

## Rules for agents

1. **Never print a secret.** Do not run `akey read`, `akey get --reveal`, or `akey export`.
   Those exist for humans and break-glass recovery. If you need a credential, inject it.
2. **Act on secrets, don't hold them.** Wrap the command that needs the credential.
3. Prefer `--json` on every call: output is a stable envelope, stdout carries only data,
   diagnostics go to stderr.
4. Nothing here prompts. Non-zero exit means failure; read `error.code`, not the prose.

## The three commands you actually need

```bash
# 1. What do I have? (names and metadata only — never values)
akey list --json

# 2. Run something with a credential injected into its environment.
#    The value never reaches your output.
akey run --with OPENAI_API_KEY=akey://openai/credential -- curl -sS https://api.openai.com/v1/models

# 3. What shape does an entry have?
akey get openai --json
```

`akey run` masks any secret that the child process prints, so even a careless `printenv`
comes back as `<concealed by akey>`.

## Coordinates

A reference is `akey://[vault/]item[/section]/field`:

```bash
akey run --with DB_PASSWORD=akey://db/password -- ./migrate
akey run --env-file .env -- node app.js     # .env holds references, not values
akey inject -i config.yml.tpl -o config.yml # resolve references inside a template
```

Query parameters: `?attribute=otp` computes a TOTP from an `otp` field, `?attribute=type|title|id`
returns metadata instead of the value.

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 2 | usage error |
| 3 | not found / ambiguous |
| 4 | locked — no identity, wrong passphrase, or this device was revoked |
| 5 | unresolved sync conflicts |
| 6 | sync failed |
| 7 | denied — policy forbids revealing this value |
| 8 | token scope — your `AKEY_TOKEN` may not touch this entry |

## If you are running with a scoped token

An operator may have given you `AKEY_TOKEN`. It is an ordinary token, not `akey_`-prefixed
is also accepted. It may be restricted to a subset of entries and may forbid reveal entirely.
Exit code 7 or 8 means you hit a limit you cannot work around — tell the operator.

## Syncing

```bash
akey sync --json
```

If it exits 5, run `akey conflicts --json`. Two devices changed the same entry; both versions
were kept. Resolve with `akey resolve <name> --ours|--theirs`, then `akey sync` again.
