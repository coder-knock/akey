# akey

[![ci](https://github.com/coder-knock/akey/actions/workflows/ci.yml/badge.svg)](https://github.com/coder-knock/akey/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/coder-knock/akey?include_prereleases&sort=semver)](https://github.com/coder-knock/akey/releases)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**An encrypted credential vault for AI agents.** One Rust binary. No daemon, no server.
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

## Install

**macOS and Linux** — downloads the release for your platform, verifies its SHA-256, and falls
back to building from source if there is no matching binary:

```bash
curl -fsSL https://raw.githubusercontent.com/coder-knock/akey/main/install.sh | sh
```

**Windows** (x86_64 and arm64):

```powershell
irm https://raw.githubusercontent.com/coder-knock/akey/main/install.ps1 | iex
```

**From source**, on any platform with [Rust](https://rustup.rs) ≥ 1.85:

```bash
cargo install --git https://github.com/coder-knock/akey --locked
```

Installer options — `--version <tag>`, `--dir <path>`, `--from-source`, `--force` — and the
equivalent `AKEY_*` environment variables are documented at the top of
[`install.sh`](install.sh) / [`install.ps1`](install.ps1).

| Platform | Prebuilt | Notes |
|---|---|---|
| macOS arm64 / x86_64 | yes | |
| Linux x86_64 / aarch64 | yes | static musl — runs on any distro regardless of glibc |
| Windows x86_64 / arm64 | yes | not yet exercised end to end; see [Status](#status) |
| anything else | — | `cargo install --git`, or `install.sh --from-source` |

The only runtime dependency is `git`, and only for `sync`. Every other command works offline.

## Five-minute start

```bash
# 1. Create a vault. Omit --remote for a purely local one.
akey init --remote git@github.com:you/akey-vault.git --device macbook --recovery
#    --recovery lets you attach a new machine later with one passphrase

# 2. Store a key — the secret goes over stdin, so it never lands in your shell history
printf 'credential=sk-...\n' | akey set openai --category apikey --stdin

# 3. See what you have (metadata only, never values)
akey list

# 4. Use it. This is the pose that matters.
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models

# 5. Move to another machine
akey init --from git@github.com:you/akey-vault.git --device laptop   # asks for the recovery passphrase
#    then, on every machine that already had the vault:
akey devices trust laptop
```

---

## Why not a plaintext `.env`

| | plaintext `.env` | akey |
|---|---|---|
| The AI reads the key | Yes — and once it is in the context, it is gone for good | No. Only the child process gets it |
| Several machines | Sync by hand | `akey sync` |
| Encryption at rest | None | age: X25519 + ChaCha20-Poly1305 |
| Laptop stolen | Rotate every key | `akey devices rm <that one>` — it stops working immediately |
| Least privilege for CI | Hand over the full key | `akey token create --allow openai --ttl 30d` |
| A compromised remote | Everything leaks | Only a directory entry is added; no ciphertext follows |
| Audit trail | None | `akey log` |

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

## Security model

1. **Each device holds its own X25519 private key**, stored only locally and never in git. The
   vault is encrypted to every device that is both an active recipient and locally approved.
2. **No KDF on the hot path.** Day-to-day commands are X25519 + ChaCha20-Poly1305 — microseconds.
   scrypt runs only during `init` and `recovery`, at roughly one second per guess for an attacker.
3. **Revealing plaintext is explicit and refusable.** `get` conceals by default; `read` is the
   plaintext channel. Both are gated by per-entry policy, `AKEY_NO_REVEAL`, and capability tokens.
4. **The remote does not decide who can read.** `recipients.json` is a directory of who exists;
   the list of who may decrypt lives in your local config and never leaves the machine. Someone who
   compromises the remote can add a public key there — it will be reported as pending and receive
   nothing until a human runs `akey devices trust`.

Lost laptop: `akey devices rm <name>` re-encrypts on the next sync. That machine can never open a
new revision again.

The threat model, nine attack simulations, and every finding with its status are in
[docs/SECURITY.md](docs/SECURITY.md).

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

`akey init` writes an `AGENTS.md` into the vault repository itself, so an agent that clones the
vault on a fresh machine can bootstrap with no external documentation.

The specification documents (REQUIREMENTS / DESIGN / TESTPLAN) are written in Chinese; the
agent-facing and landing documents are bilingual.

## Status

Crate version 0.1.0. The CLI is complete and usable: **186 unit + 40 contract + 11 end-to-end
tests**, `cargo clippy` clean, ~4 MB static release binary, worst-case vault read 54 ms on a
1000-entry vault against a 100 ms budget.

**Windows** builds and its unit tests pass, and the release workflow ships binaries for it. The
end-to-end suite drives a POSIX shell (`sh -c`, `chmod`, `/dev/null`) and is gated to Unix, so
Windows currently has compile-level and unit-level coverage rather than a proven end-to-end path.
Porting that harness is the next step there; per-file ACLs are likewise not set, and the code
instead requires the vault home to live inside the user profile.

A desktop GUI (gpuix) is the next milestone. `akey mcp` already lets an agent mount the vault
directly — metadata only, never values.

## License

MIT — see [LICENSE](LICENSE).
