# AGENTS.md — working on `akey`

`akey` is an encrypted credential store that AI agents drive from the command line.
Rust 2024, single binary, no daemon, no server.

**Reader's guide.** `docs/AGENT-INTEGRATION.md` is written for agents *using* akey —
recipes, exit-code recovery, the reference grammar, MCP wiring. `SKILL.md` is the same
material as a loadable skill definition. This file is for agents *changing* akey.
Read `REQUIREMENTS.md` (contract), `DESIGN.md` (architecture, on-disk formats, algorithms)
and `TESTPLAN.md` (what each module must prove) before touching anything.

## Build and test

```bash
cargo build                  # single binary, no OpenSSL, runtime dep is only `git`
cargo test                   # unit tests live next to the code they test
cargo test -- --ignored       # benchmarks
```

Nothing here touches the network in tests: git remotes are local `file://` bare repos.

## Non-negotiables

These are contracts, not preferences. Changing any of them is a breaking change.

1. **stdout carries data, stderr carries diagnostics.** A command that fails writes
   nothing to stdout. Tests enforce this.
2. **Exit codes are frozen** (`src/error.rs`): `0` ok, `2` usage, `3` not found/ambiguous,
   `4` locked, `5` conflict, `6` sync failure, `7` policy denied, `8` token out of scope,
   `1` internal.
3. **`--json` emits exactly one envelope**: `{"ok":true,"data":…}` or
   `{"ok":false,"error":{"code","message","hint"}}`.
4. **Nothing prompts.** No TTY means no interactive input — read from env or stdin, or fail.
5. **Secrets never leak.** No field value may appear in a log, an error message, a `Debug`
   impl, an audit record, or anything but an explicit `--reveal` / `read` / `export`.
   `Field` and `Entry` have hand-written `Debug` for exactly this reason.
6. **`Result<T, E = Error>`** — the alias keeps a defaulted error parameter.

## Layout

```
src/vault/model.rs       Vault / Entry / Field / TokenMeta — the plaintext shape
src/vault/recipients.rs  recipients.json (public keys only)
src/vault/store.rs       load/save/lock; the only thing that touches crypto
src/vault/merge.rs       merge3 — pure, deterministic, no IO
src/crypto/              the ONLY place `age` is called
src/reference.rs         akey:// parsing and resolution
src/inject/mask.rs       streaming redaction of child process output
src/inject/run.rs        env assembly + subprocess execution
src/cmd/                 one file per command group; `cli.rs` is the source of truth
assets/AGENTS.vault.md   shipped into every vault repo at `akey init`
```

## Design constraints worth knowing before you "fix" something

- **The vault is one encrypted file, merged after decryption.** Per-entry files would merge
  better in git, but a single file gives snapshot semantics and readable conflict reports.
- **Conflict copies get a reproducible ID** (`conflict_copy_id`). Two devices merging the same
  divergence must derive the *same* ULID, or every sync spawns another copy forever.
- **`recovery.age` never goes stale** because it holds a *bootstrap identity* which is always a
  vault recipient — it does not need to be rewritten when the vault changes.
- **Token hashing is SHA-256, not a KDF.** Tokens are 256-bit random; a slow KDF buys nothing
  and costs tens of milliseconds on every `akey run`.
- **`git` is a subprocess.** It reuses the user's SSH keys and credential helpers; `GIT_TERMINAL_PROMPT=0`
  and `LC_ALL=C` are set because we both non-interactively and match on its stderr text.
- **Masking holds the tail.** A secret can straddle two read chunks, so the masker must not
  conclude a byte is clean until a full window has arrived. See the comment in `mask.rs`.

## TDD

Write the test first, watch it fail for the right reason, then implement. Tests must defend
observable behaviour — an entry that a plausible bug would break. Do not assert that a field
was copied, a default was applied, or a mock was called.
