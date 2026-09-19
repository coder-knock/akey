# Contributing to akey

Thanks for considering it. This document covers what you need to get from a checkout to a merged
pull request. Issues and pull requests are welcome in **English or Chinese**.

## Before you start

`akey` is a credential vault, so a few things are held to a higher bar than usual:

- **Secrets must not appear in argv, logs, or error messages.** The test suite asserts this; new
  code should too.
- **On-disk formats and exit codes are contracts.** `AGENTS.md` lists what is frozen and why.
  Changing one is a deliberate, documented decision, not a side effect of a refactor.
- **The specification comes first.** `REQUIREMENTS.md` → `DESIGN.md` → `TESTPLAN.md` →
  implementation. If you are changing behaviour, update the spec in the same pull request.

## Setup

Rust **1.88 or newer** — set by the dependency tree rather than by edition 2024, which would need only 1.85. `git` is needed for `akey sync` and for the
test suite; nothing else.

```bash
git clone https://github.com/coder-knock/akey
cd akey
cargo build --release
```

## The checks CI runs

Run all of these before opening a pull request — CI runs exactly the same set, and a green local run
is the fastest way to a green CI.

```bash
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo test --locked
sh tests/installer.sh          # installer behaviour, with cargo and curl stubbed
```

`cargo test` covers three layers, described in `TESTPLAN.md`:

| Layer | Where | Notes |
|---|---|---|
| Unit | `src/**` `#[cfg(test)]` | Pure functions and module behaviour |
| Contract | `tests/contract.rs` | The CLI's externally observable behaviour |
| End-to-end | `tests/e2e_sync.rs` | Two machines and a real bare git remote, offline |

The end-to-end and contract suites drive a POSIX shell (`sh -c`, `chmod`, `/dev/null`) and are
gated to Unix. Windows therefore runs the unit tests only; porting that harness is a known gap and a
welcome contribution.

## What makes a test worth adding

A test earns its place by failing on a plausible bug. Concretely:

- Assert what a consumer observes — behaviour, boundaries, invariants, state transitions, real
  errors. Not wiring, field copies, defaults, or source text.
- A regression test should fail before the fix and pass after. If you cannot demonstrate that, say
  so in the pull request.
- Do not add a test just so the change "has tests". A throwaway script that proves the behaviour is
  fine for a one-off; say that that is what you did.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/), in English, imperative mood, with a
body that explains *why* when the change is not obvious:

```
fix: a write that changes nothing must not move updated_at

`set` and `edit` stamped `updated_at = now` unconditionally, so re-running an
identical `set` counted as a change. `updated_at` is what `sync` uses to pick a
merge winner, so a retried write could let older content outrank another
device's genuine edit.
```

Prefixes in use: `feat`, `fix`, `docs`, `test`, `i18n`, `build`, `chore`. Keep the subject under 72
characters. Explain the reasoning in the body, not a restatement of the diff.

## Pull requests

1. Fork, then branch from `main`. Branch names are free-form; something descriptive is fine.
2. Make the change, with the spec updated if behaviour moved.
3. Run the checks above.
4. Open the pull request and fill in the template — in particular **how you verified it**. "It
   compiles" is not verification; name the command you ran or the scenario you exercised.
5. Expect review to focus on correctness and on whether the change fits the contracts in
   `AGENTS.md`. Small, focused pull requests get reviewed quickly; a large one is easier to accept
   if it arrives as a series.

Breaking a frozen contract, changing the on-disk format, or altering an exit code needs the change
called out explicitly in the description, with the migration story.

## Reporting bugs and security issues

- Ordinary bugs: open an issue using the bug report template.
- **Security issues: do not open an issue.** Follow [SECURITY.md](SECURITY.md).
