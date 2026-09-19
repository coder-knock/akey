<!--
Thanks for the pull request. A few lines that answer the questions below are worth more than a long
description.

Do not paste secrets, vault contents, or a real akey reference string.
-->

## What this changes

<!-- One paragraph. What was wrong or missing, and what it does now. -->

## Why

<!-- The reasoning. If it fixes a bug, what was the failure mode and who hit it? -->

## How it was verified

<!--
Name the command you ran or the scenario you exercised. "It compiles" is not verification.
If you added a regression test, say whether you confirmed it fails without the fix.
-->

- [ ] `cargo test --locked` passes
- [ ] `cargo clippy --locked --all-targets -- -D warnings` is clean
- [ ] `cargo fmt --check` is clean
- [ ] `sh tests/installer.sh` passes (if installer behaviour is affected)

## Contracts

<!-- Delete the line that does not apply. See AGENTS.md for the list of frozen contracts. -->

- [ ] No frozen contract changes
- [ ] This changes a frozen contract — noted below, with the migration story

<!-- If it changes one: which contract, what breaks, and how a user moves from the old behaviour. -->

## Specification

<!-- Delete the line that does not apply. -->

- [ ] No behaviour change, so no spec change needed
- [ ] REQUIREMENTS.md / DESIGN.md / TESTPLAN.md updated in this pull request
