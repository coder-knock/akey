# Security assessment

> Scope: the `akey` CLI as of the 0.1.0 tree. The question this document answers is the one that
> matters: **can someone break in and recover plaintext?**
>
> Every claim below is either marked **[measured]** (a command was run and its output recorded) or
> **[static]** (a code path was read). Attack simulations are reproducible — §9 gives the commands.

> 中文版：[SECURITY.zh-CN.md](SECURITY.zh-CN.md)

---

## 1. Verdict

| What the attacker holds | What they get | Cost |
|---|---|---|
| The git remote, **read** access | **Nothing readable.** Only `vault.age` (age/X25519), `recipients.json` (public keys), `recovery.age` (scrypt). No private key is ever in the repo. | Must break the recovery passphrase offline — see §7 |
| One device's local directory | **Everything.** `identity.key` *is* the vault. | Trivial — but this is the declared trust boundary, not a defect |
| The git remote, **write** access | **Nothing** — see §5. A key pushed into `recipients.json` appears in the directory but is never encrypted to. | — *(was: full disclosure, retroactively)* |
| A scoped capability token | Only what `--allow` permits — **after the fixes in §4** | — |

**Bottom line.** The cryptography is not the weak link. `age` is used correctly, the recipient set
is enforced at every encryption, and no plaintext ever reaches disk or the repository. The weak
links are **policy enforcement on the CLI surface** and **the trust placed in `recipients.json`**.

**All 14 actionable findings were fixed** during this assessment, most with regression tests; the
remaining two entries are documented trade-offs, not defects. The one that took a design change
rather than a patch — remote write access yielding plaintext — is §5.

---

## 2. Threat model, as designed

- Each device holds an X25519 identity in `~/.config/akey/identity.key` (`0600`), never in git.
- `vault.age` is encrypted to every non-revoked device plus a *bootstrap* identity.
- `recovery.age` is the bootstrap identity's private key, encrypted with scrypt under a passphrase.
- The remote is assumed **untrusted for confidentiality**: "the repo holds only ciphertext".
- Capability tokens are read-only and scope-limited.

What the design did **not** model: an attacker with **write** access to the remote. That gap is A1.

---

## 3. Attack simulations

Each was run end-to-end against the release binary with two temporary `HOME`s and a local bare
repository. No mocks.

### 3.1 Plaintext-leak sweep — **clean** [measured]

Built a vault holding a canary, then exercised `get` / `get --reveal` / `read` / `list` / `run` /
`inject` / `export` / `doc put` / `doc get` / `edit` / `token create` / `log` / `doctor` / `sync`,
then scanned:

- every file in the vault working tree
- **every git object across all revisions** (`git grep <canary> $(git rev-list --all)`)
- every file in the local private directory (including `audit.log`)

**Result: the canary appears nowhere outside the in-memory decryption path.**

File modes after `init`: `$AKEY_HOME` `0700`; `identity.key` / `config.toml` / `audit.log` /
`vault.lock` `0600`. Verified [measured].

### 3.2 Recipient injection → full disclosure [measured] — **A1, open**

```
attacker: akey init --device attacker            # one command, no privileges
attacker: git clone <remote>; edit recipients.json to add its own public key; git push
victim:   akey sync                              # silently accepts; exit 0, no warning
victim:   akey set openai --stdin; akey sync     # re-encrypts to ALL active recipients
attacker: point config.toml at the clone; akey read akey://openai/credential
          → sk-ROTATED-AFTER-ATTACK              # and every entry written BEFORE the attack too
```

### 3.3 Revocation reversal via fast-forward [measured] — **A2, fixed**

```
alpha: akey devices rm beta                      # beta leaves the recipient set
beta (revoked, still has git write access):
       git fetch; git reset --hard origin/main   # catch up
       edit recipients.json to clear its own revoked_at
       git commit; git push                      # an ordinary, non-forced push
alpha: akey sync                                 # fast-forward path
       → beta is active again on alpha
alpha: akey set openai --stdin; akey sync
beta:  akey read akey://openai/credential
       → sk-AFTER-REVOKE                         # revocation undone, in one round trip
```

Root cause: `merge_recipients` implements "revocation wins", but the **fast-forward branch never
called it** — it replaced the whole working tree, including `recipients.json`, with the remote's copy.

### 3.4 Scoped token → privilege escalation [measured] — **A5, fixed**

Holding a token issued with `--allow openai` and no write rights:

```
akey --json token create --name pwned            → exit 0   # minted an UNRESTRICTED token
akey --json devices add --name backdoor          → exit 0
akey --json recovery set                         → exit 0   # planted its own recovery passphrase
akey --json set evil --stdin                     → exit 7   # correctly denied
akey --json rm openai                            → exit 7   # correctly denied
```

`token create` was the worst of these: a token scoped to one entry could mint a token scoped to
nothing, then read the entire vault. The scope was self-defeating.

### 3.5 Reveal-policy bypasses [measured] — **A3 / A4 / A6 / A8 / A9 / A10, fixed**

```
AKEY_NO_REVEAL=1 akey read akey://acct/password   → exit 7   # correct
AKEY_NO_REVEAL=1 akey inject <<< 'x=akey://acct/password'
                                                  → plaintext on stdout, exit 0   # A3
entry reveal=deny; akey get acct                  → otp seed printed in the clear  # A4
entry reveal=deny; akey export --yes              → plaintext for that entry       # A6
akey run --no-masking …                           → not refused under a reveal ban # A8
akey run --with A="Bearer akey://acct/password" -- sh -c 'echo ${A#Bearer }'
                                                  → CANARY-PW-123456              # A9
akey --dry-run read akey://acct/password -o /tmp/x  → wrote 17 bytes              # A10
```

### 3.6 Masking limits [measured] — accepted, documented

```
akey run --with S=akey://acct/password -- sh -c 'echo direct=$S'
  → direct=<concealed by akey>
akey run --with S=akey://acct/password -- sh -c 'printf %s "$S" | base64'
  → Q0FOQVJZLVBXLTEyMzQ1Ng==            # evades masking
```

Masking protects against **accidental echo**. It is not, and cannot be, a boundary against a
hostile child process: that process already holds the plaintext in its environment and can encode,
split across stdout/stderr, or write it to a socket. Treat `akey run` as an ergonomic guardrail.

### 3.7 MCP surface — **clean** [measured]

Malformed JSON → `-32700` with a generic message and **no echo of the payload**. Extra `arguments`
fields ignored. A conflict-copy name → `no entry named …`. `tools/call` returns only
`label`/`type`/`concealed`/`reference` — **never a value**.

### 3.8 Rollback of the remote — revocation **held** [measured]

Hard-resetting the bare repository to a pre-revocation commit did **not** un-revoke the device:
`merge_recipients` is sticky. (This was the weaker variant; §3.3 is the one that got through.)

### 3.9 Dependency audit — **clean** [measured]

`cargo audit` and `cargo deny` cannot run here: the local advisory-db contains CVSS 4.0 entries
that both parsers reject. Worked around by matching `Cargo.lock` against the advisory database
directly.

- 252 packages in the lockfile
- 42 RustSec advisories match those crates by name
- **0 of them affect our versions** (all are covered by `patched` / `unaffected`)
- The matcher was validated against known-patched advisories (e.g. `age 0.12.1` vs
  RUSTSEC-2024-0433, patched at `>= 0.11.1`) so the null result is meaningful.

---

## 4. Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| **A1** | **Critical** | Remote write access → recipient injection → retroactive full plaintext | **Fixed + test** — see §5 |
| A2 | High | Fast-forward path bypassed "revocation wins"; a revoked device re-admitted itself | Fixed + test |
| A3 | High | `inject` was a plaintext egress that skipped every reveal gate | Fixed + test |
| A4 | High | `otp` fields were not concealed → the TOTP **seed** printed by default | Fixed + test |
| A5 | High | A scoped token could mint an unrestricted token and plant its own recovery passphrase | Fixed + test |
| A6 | Medium | `export` ignored per-entry `reveal=deny` | Fixed + test |
| A7 | Medium | `sync` used `git add -A`, so plaintext strayed into the repo got committed and pushed | Fixed |
| A8 | Medium | `run --no-masking` was allowed under a reveal ban | Fixed + test |
| A9 | Medium | Composite values (`Bearer <ref>`) were masked only as a whole; the bare segment leaked | Fixed |
| A10 | Medium | `--dry-run` still wrote plaintext files via `read -o` / `inject -o` | Fixed |
| A11 | Low | Weak recovery passphrase accepted from env/stdin; the length floor only applied to the TTY path | Fixed + test |
| A12 | Low | `recovery rotate` was a silent no-op non-interactively (both reads hit the same env var) | Fixed + test |
| A13 | Low | Two `recovery set` runs accumulated bootstrap identities | Fixed + test |
| A14 | Info | Dead surface: `Config.reveal_allowed` was documented but never read; `--debug` and `doctor --agent` did nothing; assignment parsing rejected the `field[[type]]` form the design document specified | Fixed |
| A15 | Info | Metadata: device names, commit timestamps, approximate entry count (by ciphertext size) | By design |
| A16 | Info | Masking is a guardrail, not a sandbox (§3.6); TOTP codes are displayed by design | By design |

Notable non-findings, i.e. things that were checked and are **sound**:

- `age` usage: multi-recipient encryption, no nonce reuse, no partial plaintext on decrypt failure,
  non-deterministic ciphertexts, zero-recipient encryption refused.
- Constant-time token comparison (`subtle`), SHA-256 over a 256-bit random secret.
- `identity.key` never printed; the only `expose_secret()` call sites are `save()` and the
  `recovery.age` payload.
- No `unwrap`/`expect`/`panic` on a value-bearing path in production code → no memory dump via panic.
- Every error message that names a subject names the **entry**, never the value.

---

## 5. A1 — remote write access, and how it was closed

`recipients.json` is distributed by the remote and was adopted without any authentication. Anyone
who could write to it added a public key, and the next legitimate write re-encrypted the entire
vault — history included — to that key. This defeated the design's central promise: the remote was
treated as untrusted for *reading* while being implicitly trusted for *writing*.

**The fix: a local trust set.**

`recipients.json` now answers "who exists". A second set, in `~/.config/akey/config.toml` and never
synced, answers "who is allowed to decrypt". Encryption uses the intersection.

- `Store::save_with` still writes the full directory — devices have to see each other — but encrypts
  only to locally approved keys.
- A key present in the repository without approval is reported as **pending** by `akey sync` and
  `akey doctor`, and receives nothing.
- `akey devices trust <name|pubkey>` approves one and immediately re-encrypts the current vault to
  it, so it does not have to wait for the next write; `akey devices untrust` reverses that.
- `akey init` trusts the machine itself. `akey init --from` trusts the recipients already in the
  vault at bootstrap time: those are exactly the machines that could open the vault whose recovery
  passphrase the operator just supplied, so handing over that passphrase is the trust anchor. Keys
  appearing **after** bootstrap are never auto-trusted.
- `akey devices rm` drops the key from the trust set as well as from the directory.

**The cost** is one extra command on every *other* device when a new one joins:

```bash
akey devices trust laptop
```

**Regression test:** `tests/e2e_sync.rs::an_injected_recipient_never_receives_ciphertext` replays
the full attack — clone the remote, add a public key, push — and asserts that the injected key is
surfaced as pending and stays locked out (exit 4) even after the victim writes again.

**Residual (R8).** A device that bootstraps *after* an injection inherits the injected key through
the "trust what was already there" rule. Closing that would require the joining device to prove it
decrypted the vault — and without a signature primitive (age's X25519 cannot sign), that means every
existing device would have to verify the recovery passphrase itself. Not implemented; documented.

## 6. Residual risks

| | Risk | Why it is accepted |
|---|---|---|
| R1 | `identity.key` is a single point of failure | Inherent: it *is* the device. `0600` + `ensure_private` on every read |
| R2 | A secret in argv is visible to `ps` and shell history | Warned at runtime; `--stdin` is the documented path |
| R3 | Injected values live in the child's environment | Inherent to environment injection; same as every env-based tool |
| R4 | Plaintext copies in process memory are not all zeroized (age's `StaticSecret` has no `Drop` zeroize) | Short-lived CLI process; matters only against core dumps / swap / same-uid ptrace |
| R5 | Masking evades on re-encoding (§3.6) | Documented; masking is not the boundary |
| R6 | Metadata leaks (device names, timing, entry count) | A single encrypted file hides entry *names* by design; git inherently timestamps commits |
| R7 | `age 0.12` is pre-1.0 and upstream calls it "for testing purposes only" | Pinned; the format is a stable public spec, and correctness is covered by our own round-trip tests |
| R8 | A device bootstrapping after an injection inherits the injected key | See §5. Requires a signature primitive to close properly |

---

## 7. Cryptographic parameters [measured]

| | Value |
|---|---|
| Vault | age v1, X25519 recipients, ChaCha20-Poly1305 |
| Recovery | age passphrase mode, scrypt |
| scrypt cost (this machine) | ~2.0 s and 512 MiB per guess (`log_n≈19–20`) |
| Token hash | SHA-256 over a 256-bit random value, compared in constant time |
| Hot path (1000-entry vault, 300 KB) | worst-case read 53.7 ms — budget is 100 ms |

Offline cost of attacking a leaked `recovery.age`, at ~1 guess/s/core:

| Passphrase | Search space | Time |
|---|---|---|
| 1 character | 26 | instant |
| 6 lowercase | 2.6e8 | ~36 days on 100 cores |
| 12 lowercase | 9.5e16 | ~3 million years |
| 6-word diceware | 2.2e23 | ~10 million years |

The 12-character floor (A11) is therefore load-bearing: the recovery passphrase is the **only**
protection for a leaked repository. Prefer a multi-word passphrase; a 12-character human-chosen
string is not 12 characters of entropy.

---

## 8. How the assessment was performed

Two read-only `security-reviewer` agents worked the code paths (plaintext egress; crypto and trust
model) while the maintainer ran black-box attacks against the release binary. The agents' sandbox
was read-only and offline, so every dynamic claim was executed by the maintainer and the raw output
returned to them; their static findings were then verified empirically before being accepted.

Each fix was validated by **re-running the attack**, not by re-reading the patch. A2 and A5 were
confirmed exploitable before the fix and confirmed dead after it; both now have regression tests
(`tests/e2e_sync.rs::revocation_survives_a_fast_forward`,
`tests/contract.rs::a_scoped_token_cannot_mutate_admin_state`).

## 9. Reproducing

```bash
cargo build --release

# 3.2 recipient injection
#   create two temp HOMEs, a bare remote, `akey init --remote`, then add your own
#   public key to recipients.json in a clone and push. Any later `akey set` + `akey sync`
#   on the victim re-encrypts to you.

# 3.3 revocation reversal
#   after `akey devices rm <name>`, fast-forward that device to origin/main, clear its own
#   revoked_at, commit and push, then `akey sync` elsewhere.

# 3.4 token escalation
akey --json token create --name narrow --allow openai
AKEY_TOKEN=<token> akey --json token create --name pwned      # must exit 7

# 3.5 reveal bypasses
printf 'x=akey://acct/password\n' | AKEY_NO_REVEAL=1 akey inject       # must exit 7
akey --dry-run read akey://acct/password -o /tmp/should-not-exist      # must not write

# 3.9 dependencies
cargo audit    # if the local advisory-db parses; otherwise match Cargo.lock against RustSec
```
