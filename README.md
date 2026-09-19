# akey

**An encrypted credential vault for AI agents.** One Rust binary, no daemon, no server.
Ciphertext syncs between your machines through a git remote you already own.

It solves one problem: **let an agent use a secret without ever seeing it.**

```bash
# The agent needs OpenAI. The plaintext never enters its context.
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS https://api.openai.com/v1/models
```

The child process gets the real value. The agent's stdout gets `<concealed by akey>`.

> 中文文档：[README.zh-CN.md](README.zh-CN.md) · [docs/AGENT-INTEGRATION.zh-CN.md](docs/AGENT-INTEGRATION.zh-CN.md)

---

## Why not a plaintext `.env`

| | plaintext `.env` | akey |
|---|---|---|
| The AI reads the key | Yes — and once it's in the context, it's gone for good | No. Only the child process gets it |
| Several machines | Sync by hand | `akey sync` |
| Encryption at rest | None | age: X25519 + ChaCha20-Poly1305 |
| Laptop stolen | Rotate every key | `akey devices rm <that one>` — it stops working immediately |
| Least privilege for CI | Hand over the full key | `akey token create --allow openai --ttl 30d` |
| Audit trail | None | `akey log` |

---

## Install

```bash
cargo build --release        # one binary; no OpenSSL, no daemon
install -m755 target/release/akey /usr/local/bin/akey
```

The only runtime dependency is `git`, used for sync. Every command except `sync` works offline.

## Five-minute start

```bash
# 1. Create a vault. Omit --remote for a purely local one.
akey init --remote git@github.com:you/akey-vault.git --device macbook --recovery
#    --recovery lets you attach a new machine later with a single passphrase

# 2. Store a key — the secret goes over stdin, so it never lands in your shell history
printf 'credential=sk-...\n' | akey set openai --category apikey --stdin

# 3. See what you have (metadata only, never values)
akey list

# 4. Use it. This is the pose that matters.
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models

# 5. Move to another machine
akey init --from git@github.com:you/akey-vault.git --device laptop   # asks for the recovery passphrase
```

## Command index

| | Commands |
|---|---|
| Lifecycle | `init` · `devices` · `recovery` · `token` · `sync` · `conflicts` · `resolve` |
| Entries | `get` · `set` · `edit` · `rm` · `restore` · `cp` · `mv` · `list` · `template` · `doc` |
| Delivery (for agents) | `run` · `inject` · `read` · `mcp` |
| Operations | `whoami` · `doctor` · `log` · `schema` · `completion` |
| Migration | `export` · `import` |

The machine-readable equivalent is `akey schema --json`. This README deliberately does not
duplicate it — **agents should treat `schema` as the source of truth.**

## Security model in three sentences

1. **Each device holds its own X25519 private key**, stored only locally (`0600`), never in git.
   The vault is encrypted to every non-revoked device's public key.
2. **No KDF on the hot path.** Day-to-day commands are X25519 + ChaCha20-Poly1305 — microseconds.
   scrypt runs only during `init` and `recovery`.
3. **Revealing plaintext is explicit and refusable.** `get` conceals by default; `read` is the
   plaintext channel. Both are gated by per-entry policy, `AKEY_NO_REVEAL`, and capability tokens.

Lost laptop: `akey devices rm <name>` re-encrypts on the next sync. That machine can never
open a new revision again.

## Documentation

| | Reader | Contents |
|---|---|---|
| **[docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md)** | **AI agents** | How to integrate, how to recover from each exit code, what never to do |
| **[SKILL.md](SKILL.md)** | **agent harnesses** | The same material as a loadable skill definition |
| **[docs/SECURITY.md](docs/SECURITY.md)** | **security reviewers** | Threat model, attack simulations, findings and their status |
| [AGENTS.md](AGENTS.md) | agents **changing** akey | Architecture, conventions, frozen contracts |
| [REQUIREMENTS.md](REQUIREMENTS.md) | humans | Requirements and external contracts, incl. a feature-by-feature 1Password CLI comparison |
| [DESIGN.md](DESIGN.md) | humans | Data model, on-disk formats, algorithms, error taxonomy |
| [TESTPLAN.md](TESTPLAN.md) | humans | What each layer must prove |

`akey init` writes an `AGENTS.md` into the vault repository itself, so an agent that clones
the vault on a fresh machine can bootstrap with no external documentation.

The specification documents (`REQUIREMENTS` / `DESIGN` / `TESTPLAN`) are currently written in
Chinese; the agent-facing and landing documents are in both languages.

## Status

CLI is complete and usable: **185 unit + 33 contract + 8 end-to-end tests**, `cargo clippy` clean,
4.0 MB release binary. A desktop GUI (gpuix) is the next milestone. `akey mcp` already lets an
agent mount the vault directly — metadata only, never values.

## License

MIT — see [LICENSE](LICENSE).
