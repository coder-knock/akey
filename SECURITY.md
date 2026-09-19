# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Two channels, either is fine:

- **GitHub private vulnerability reporting** — the *Report a vulnerability* button on the
  [Security tab](https://github.com/coder-knock/akey/security/advisories/new). Preferred, because
  the whole discussion stays private and inside GitHub.
- **Email** — `opensource@coderknock.com`, with `akey security` in the subject.

Please include:

- the version or commit you tested (`akey --version`, or the output of `git rev-parse HEAD`);
- your platform and Rust version;
- what you did, what happened, and what you expected;
- a proof of concept if you have one — a short script or a sequence of commands is ideal.

If you are unsure whether something is exploitable, report it anyway. A hunch is a useful report.

## What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix, or a documented decision not to fix | within 90 days |

You will be credited in the release notes unless you would rather not be. If a timeline slips, you
will be told rather than left waiting.

## Scope

**In scope** — the properties this project actually claims:

- Recovering plaintext without the device identity or the recovery passphrase.
- A secret reaching a party that should not see it: the caller's stdout, argv, logs, error
  messages, or a device that is not an approved recipient.
- Making a device that was removed with `akey devices rm` able to read new revisions.
- Getting a recipient this machine never approved to receive ciphertext.
- Losing or corrupting vault content through a failed or interrupted operation.

**Out of scope** — not because these do not matter, but because they are not promises `akey` makes:

- Anything that requires the attacker to already hold the device identity or the recovery
  passphrase. At that point the vault is open by design.
- The cryptographic strength of the `age` format itself; that is [upstream](https://age-encryption.org).
- A compromised OS account, a keylogger, a memory dump, or physical access to an unlocked machine.
- Denial of service against your own machine, or against a vault you already control.
- The gaps listed under *Platform support* in the README — the end-to-end suite not yet covering
  Windows is a known limitation, not a vulnerability.

## Relationship to the threat model

[`docs/SECURITY.md`](docs/SECURITY.md) is the substantive document: the threat model, nine attack
simulations, and every finding with its current status, including the trade-offs that were accepted
deliberately. **Read it before reporting.** Several things that look like bugs are recorded there as
conscious decisions, and a report that engages with the existing analysis is far more useful than
one that rediscovers it.
