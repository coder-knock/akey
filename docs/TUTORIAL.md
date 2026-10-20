# `akey` — a one-evening tutorial

> One scenario, walked step by step. Every command in this document was run against the binary on
> the machine you're reading this on; the only thing you'll change is the values that aren't
> secret and the secrets that are.
>
> 中文版：[docs/TUTORIAL.zh-CN.md](TUTORIAL.zh-CN.md)

## The scenario

You have **two machines** — a laptop and a desktop — and an **AI agent** (Claude Code, Codex,
whatever you use) on the desktop. You want all three to use the same OpenAI API key without any
of them ever seeing the plaintext. You want to rotate that key from either of them and have the
other pick it up. You want CI to be able to call the API without holding the same trust level as
your laptop.

That is the whole product. The rest of this document walks it.

---

## 0. Setup checklist (one minute)

```bash
akey --version            # ≥ 0.1.0
akey schema --json | head  # prints the machine-readable command surface
git --version              # sync is the only command that touches the network
```

Pick a git remote you already own. GitHub, Gitee, a self-hosted Gitea, whatever. The remote stores
**only ciphertext**, so its visibility doesn't matter cryptographically — but a private repo keeps
noise out of public issue trackers. Examples in this doc use `git@github.com:you/akey-vault.git`;
substitute yours.

Two non-secret environment variables you'll set repeatedly through this tutorial. Put them in your
shell rc if you like; nothing here depends on them being set:

| Var | What |
|---|---|
| `AKEY_HOME` | Override the local private dir (default `~/.config/akey`) |
| `AKEY_DEVICE_NAME` | Default device name for `init` |

---

## Step 1 — initialize the vault on machine #1

Open a shell on the laptop. Run one command:

```bash
akey init \
  --remote git@github.com:you/akey-vault.git \
  --device macbook \
  --recovery
```

`--recovery` makes the CLI ask for a passphrase. Pick one with at least 12 characters (it'll
refuse shorter ones — that's the rule, not a bug). **This passphrase is the only way to attach a
new device later if this laptop is lost.** Store it in a password manager, not on the laptop.

What just happened, in three facts:

- A new X25519 keypair was generated at `~/.config/akey/identity.key`, mode `0600`.
- The vault repository was initialised at `~/.config/akey/repo` and pushed to your remote.
- A **bootstrap identity** was added to the recipient set, and its private key was wrapped with your
  passphrase into `recovery.age`. Bootstrap identities never need to be re-encrypted — they're
  always vault recipients.

Sanity check:

```bash
akey whoami --json
```

```json
{"ok":true,"data":{"device":"macbook","devices":1,"entries":0,"home":"/Users/you/.config/akey",
 "pubkey":"age1…","remote":"git@github.com:you/akey-vault.git",
 "repo":"/Users/you/.config/akey/repo","token_scope":null,"tokens":0,"vault":"default"}}
```

If `whoami` exits **4** here, your identity was not created — usually a permission problem on
`~/.config/akey`. `akey doctor --json` will tell you which check failed and how to fix it.

---

## Step 2 — store your first key

Two rules worth memorising before you type anything else:

1. **Secrets go over stdin, never in argv.** Anything you put on the command line lands in shell
   history, in `ps`, and in any audit log the terminal keeps.
2. **Names are unique, IDs are stable.** A name is what you type; an ID is a 26-character ULID that
   survives renames. Use names interactively, IDs in scripts.

```bash
printf 'credential=sk-proj-9f2a7c1e4b\n' | \
  akey set openai --category apikey --stdin
```

Expected output:

```
created entry 'openai' (01M2WXY5TV8EQ0NT1PH813DKG1, 2 field(s))
```

Two fields because the `apikey` template ships with `credential` *and* `url`. The `credential` is
the secret, the `url` is just the API endpoint label — set it next:

```bash
akey set openai url=https://api.openai.com/v1
```

Now look at the vault:

```bash
akey list --json
```

```json
{"ok":true,"data":{"count":1,"entries":[{
  "category":"apikey","id":"01M2WXY5TV8EQ0NT1PH813DKG1",
  "name":"openai","field_count":2,
  "tags":[],"favorite":false,"expires_at":null,"deleted_at":null}]}}
```

The vault is encrypted; `list` shows metadata only. To see the *shape* of one entry (field names,
types, and the references you'll feed to `--with`):

```bash
akey get openai --json | jq -r '.data.fields[] | "\(.id) (\(.type)) → \(.reference)"'
```

```
credential (concealed) → akey://default/openai/credential
url (url)              → akey://default/openai/url
```

**The reference is the thing you actually wanted.** The plaintext value never has to appear in
your prompt, your logs, or your transcript.

---

## Step 3 — use the key from an agent

This is the pose the whole product is built around. **The agent wraps the command that needs the
credential; the secret goes into the child's environment, not into the agent's context.**

```bash
akey run \
  --with OPENAI_API_KEY=akey://openai/credential \
  -- curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models
```

What you see in your terminal is the JSON model list. What your agent would see, if it ran the
same command, is *exactly the same* — there's no separate "agent channel". The agent can hand
this command line to you and the secret still never appears in its context.

A subtler guarantee: even if the child process *tries* to print the secret back at you, the
masker intercepts it.

```bash
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  sh -c 'echo "got=$OPENAI_API_KEY"'
```

```
got=<concealed by akey>
```

The shell substitution *ran* (the variable was set), but the byte sequence that matches the secret
was replaced in the captured output. **Caveat:** the masker only fires on values of 8 characters
or longer — anything shorter would turn ordinary output (`true`, `0`, `us-east-1`) into mosaic.
Don't use short secrets with `run` and assume they're protected.

Other useful forms of `--with`, all equivalent for this entry:

```bash
akey run --with OPENAI_API_KEY=akey://openai/credential -- …   # explicit reference (preferred)
akey run --with OPENAI_API_KEY=openai                -- …     # short form: takes the default secret field
akey run --with openai                                -- …    # variable name derived from entry name → OPENAI_API_KEY
```

When the child is an existing project that already has a `.env`:

```bash
# .env
OPENAI_API_KEY=akey://openai/credential

akey run --env-file .env -- npm start
```

`--env-file` resolves every `akey://…` reference it finds and injects the resolved values into the
child's environment. `.env` itself holds no plaintext and is safe to commit.

---

## Step 4 — push it so the desktop can see it

```bash
akey sync --json
```

```json
{"ok":true,"data":{"result":"pushed","entries":1,"devices":1,"conflicts":0}}
```

If this is the first push you'll be asked to confirm the remote (`-y` to skip next time). After
that, `sync` is one command: fetch, merge if needed, push.

Exit codes to memorise for `sync`:

| Code | Meaning | What you do |
|---|---|---|
| 0 | pushed / pulled / already up to date | nothing |
| 5 | conflicts were created during merge | run `akey conflicts --json`, pick a side, `sync` again |
| 6 | git/remote broken | check `git ls-remote`, retry once |

`5` is the one that surprises people. **Nothing was lost** — the merge succeeded and was pushed;
`ours` kept the original name, `theirs` became `<name>.conflict.<short-id>`. Exit 5 is the machine
telling you "a human needs to pick a side", not "your data is gone".

---

## Step 5 — bring up machine #2 (desktop) and use the same key

On the desktop:

```bash
akey init --from git@github.com:you/akey-vault.git --device desktop
```

This asks for the recovery passphrase. If you forgot it, *stop here* — there's no fallback, and
this is the only design point where akey is genuinely unforgiving. The binary will:
- fetch the vault,
- decrypt `recovery.age` with your passphrase,
- mint a new device identity,
- add the new device to `recipients.json`,
- re-encrypt `vault.age` to include the new device,
- commit and push.

Then on **machine #1** (the laptop) approve the new device. This step is what blocks the "remote
adds a rogue public key" attack — `recipients.json` is just a directory, and encryption only goes
to the **intersection** of the repository's recipient set and your local trust set:

```bash
akey devices trust desktop
```

Back on the desktop, the key is now usable:

```bash
akey list
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models | head
```

---

## Step 6 — rotate the key

You do this on whichever machine is convenient. The plaintext goes over stdin, exactly like step 2:

```bash
printf 'credential=sk-proj-rotated-9c4a\n' | akey set openai --stdin
akey sync                       # laptop pushes
```

On the desktop, the next `sync` (or the next `run`) pulls the rotation:

```bash
akey sync
akey get openai --json | jq '.data.fields[0].rotated_at'   # timestamp moved
```

If you want the metadata to clearly say "I rotated this on purpose" (so `list` can flag stale
keys):

```bash
akey edit openai --rotate
```

To stop this entry from ever being revealable in plaintext (injection keeps working):

```bash
akey edit openai --reveal-policy deny
```

> **Don't want to think up a strong value yourself?** `akey generate` ships its own password
> generator and diceware passphrases — `akey generate no-ambiguous,24` or
> `akey generate passphrase,5` — see Step 10. Pipe the result straight into `set --stdin`.

---

## Step 7 — give CI a scoped, read-only credential

You do **not** give CI your device identity. CI gets a capability token that:

- can only inject entries in its `--allow` list,
- cannot fetch plaintext (`--deny-reveal`),
- cannot modify anything (writes always exit **7**),
- expires automatically.

On the laptop:

```bash
akey token create --name ci-openai --allow openai --deny-reveal --ttl 30d
```

```
token 'ci-openai' issued — copy it now, it will never be shown again
akey_3plcjEBH0qqPuqo6GW-spn-1Ky-yMLJNLiQ95sZrwcI
```

The plaintext token is shown **exactly once**. Put it in your CI's secret store as `AKEY_TOKEN`:

```yaml
# .github/workflows/example.yml (sketch — adapt to your platform)
- env:
    AKEY_TOKEN: ${{ secrets.AKEY_TOKEN }}
  run: |
    akey run --with OPENAI_API_KEY=akey://openai/credential -- |
      python ./build_embeddings.py
```

The same token, invoked from CI:

```bash
AKEY_TOKEN=akey_3plc…  akey run --with OPENAI_API_KEY=akey://openai/credential -- …
```

What the CI process can and cannot do, verified:

```bash
# ✅  In scope, injection only:
AKEY_TOKEN=akey_3plc… akey run --with OPENAI_API_KEY=akey://openai/credential -- …

# ❌  Trying to write anything:
AKEY_TOKEN=akey_3plc… akey set github --category apikey credential=foo
# → exit 7, "this command is running with AKEY_TOKEN, which is a read-only capability"

# ❌  Trying to read the plaintext directly:
AKEY_TOKEN=akey_3plc… akey get openai --reveal
# → exit 7, "denied by --deny-reveal"

# ❌  Reaching for an entry that isn't in --allow:
AKEY_TOKEN=akey_3plc… akey run --with GITHUB_TOKEN=akey://github/credential -- …
# → exit 8, "token_scope"
```

If CI is compromised, the blast radius is one entry for up to 30 days. Revoke earlier if you
want:

```bash
akey token rm ci-openai
```

Tokens are revoked immediately on the laptop's next `sync`. The compromised token can't decrypt
anything new; whatever it had cached in memory is the only exposure window.

---

## Step 8 — what an agent actually sees, end to end

Putting it all together, this is what your AI assistant runs when it needs to call OpenAI. You can
hand it this prompt; it will figure out the rest from `schema`:

> Use `akey` to call the OpenAI models endpoint. The vault name is `default`. Don't `akey read`
> anything.

What the agent does:

```bash
akey whoami --json                       # sanity-check it's on a set-up machine
akey schema --json | jq '.commands[] | .name'   # the authoritative command list
akey list --json                         # what entries exist
akey get openai --json | \
  jq -r '.data.fields[] | select(.concealed) | .reference'
# → akey://default/openai/credential
akey run --with OPENAI_API_KEY=akey://openai/credential -- \
  curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
       https://api.openai.com/v1/models
```

The agent never sees the key. It sees `<concealed by akey>` if anything it runs echoes the value
back, which is exactly what you want — a leak that the agent notices is a leak that's been
defanged.

---

## Step 9 — laptop stolen

On the laptop you still have:

```bash
akey devices rm macbook
akey sync
```

This re-encrypts `vault.age` *without* the stolen device's public key in the recipient set, and
pushes. The thief has an `identity.key` that no longer matches anything in the repository. **You
do not need to rotate every key the laptop ever touched** — only the ones you care were on it.

If the laptop didn't have `--recovery` set up, the only other consequence is that *you* can't
bootstrap a new machine either. Set up recovery today if you haven't.

---

## Step 10 — generate, audit, and the `password` category

### Generate without storing

```bash
akey generate                              # letters,digits,symbols,32
akey generate no-ambiguous,24              # no 0/O/1/l/I/| — easier to read aloud
akey generate hex,40                       # 40 hex chars
akey generate passphrase,5                 # five EFF diceware words, joined by `-`
akey generate --json letters,16            # {"ok":true,"data":{"password":"…"}}
```

Recipes:

| Token          | What |
|---|---|
| `letters`, `digits`, `symbols` | the three character sets (OR-combined if you list several) |
| `no-ambiguous` | drop `0 O 1 l I |` from whatever pool you have so far |
| `hex`, `base32`, `base64`     | replace the pool with the respective alphabet |
| `passphrase`  | EFF short word list, length is **word count**, default 5 |
| `<n>`         | explicit length (1..=4096 for chars, 1..=10 for words) |

`passphrase` and the character-set tokens are mutually exclusive — combining them is a usage
error (exit 2). All generation is local; nothing touches the network, the audit log, or even a
vault.

### Audit the vault

```bash
akey audit                                 # human-readable
akey audit --json                          # grouped by weakness
akey doctor --json                         # same checks, machine-readable, with severity
```

`audit` and `doctor` together catch four classes of problem:

- **Weak secrets** — value shorter than 8 characters, single-character-set, or in the bundled
  top-1000 list.
- **Reused secrets** — two entries holding the same value.
- **Stale rotations** — `apikey` / `token` entries whose `rotated_at` is more than a year old.
- **Expiring** — entries with `expires_at` inside the next 30 days (already there pre-v0.3).

The output **never contains the value or any hash of it** — only the entry name, the field id,
and a reason. (`tests::audit_check_never_includes_value_or_hash` enforces this contract.)

### The `password` category

For "a single password" — a WiFi PSK, a database root password you don't want to file under
`database`, an app-specific secret with no username or URL — use the new first-class
`password` category:

```bash
akey set wifi-home --category password --title "Home WiFi" --generate-password=no-ambiguous,24
akey get wifi-home --json | jq -r '.data.fields[0].reference'
# → akey://default/wifi-home/password
akey run --with WIFI_PSK=akey://wifi-home/password -- …         # inject without seeing
```

It has exactly one field (`password`, concealed) — no `username`, no `url`. The shape is what
you actually want to store when you don't want a category-shaped skeleton getting in the way.

### Tighten the recovery passphrase later

The minimum recovery passphrase length is 12 by default. If your security policy wants 16 or
20:

```bash
akey recovery rotate --min-passphrase-len 20        # new passphrase must be ≥ 20 chars
akey recovery status --json                          # configured / min / current length / strength
```

`recovery status` reports the **length** and a coarse strength bucket — never the passphrase
itself.

---

```bash
# Discover
akey schema --json                    # authoritative command surface
akey whoami --json                    # device, repo, entry count, public key
akey doctor --json                    # permission / remote / token / audit / conflict check
akey list --json                      # entries (metadata only)
akey audit --json                     # weak / reused / stale / expiring (no values)
akey get <name> --json                # one entry (metadata + references)

# Generate
akey generate                         # letters,digits,symbols,32
akey generate <recipe>                # see Step 10 for the grammar

# Edit
printf 'credential=…\n' | akey set <name> --category <K> --stdin
akey edit <name> --title … --tags … --favorite --rotate --reveal-policy deny
akey mv <old> <new>                   # rename; ID is stable so refs keep working
akey rm <name>                        # soft delete (restorable)
akey rm <name> --purge                # hard delete (irreversible)
akey restore <name>
akey doc put <name> <file> --field <f> # attach a binary file (kubeconfig, SA json)
akey doc get akey://<name>/<f> -o <file>

# Sync & devices
akey sync --json
akey devices list
akey devices trust <name>             # run on every existing machine
akey recovery set | rotate | unlock

# Deliver (for agents)
akey run --with VAR=akey://item/field -- <cmd>
akey run --env-file .env -- <cmd>
akey run --bundle <env-bundle-name> -- <cmd>
akey inject -i config.yml.tpl -o config.yml
akey mcp                              # JSON-RPC over stdio; metadata only

# CI
akey token create --name … --allow … --deny-reveal --ttl 30d
AKEY_TOKEN=akey_… akey run --with … -- <cmd>
akey token list
akey token rm <name>
```

## What you must never do

These are not style preferences; they break the security model:

| Never | Why | Do this instead |
|---|---|---|
| `akey read <ref>` / `akey get --reveal` | Plaintext enters your context irreversibly | `akey run --with … -- <command>` |
| `akey export …` | Dumps the whole vault to disk in the clear | inject only what you need |
| `akey set x credential=sk-…` (value in argv) | Lands in shell history and `ps` | `printf 'credential=…\n' \| akey set x --stdin` |
| Printing `AKEY_TOKEN` | It is a credential | keep it in the environment |
| Working around exit 7 / 8 | Those are policy, not obstacles | change path, or ask a human |
| Editing files inside the vault repo directly | It is ciphertext; you'll corrupt it | always go through the CLI |
| Copying `identity.key` to another machine | Device revocation stops working | `akey init --from <url>` + recovery passphrase |

## When to stop and ask a human

1. `whoami` exits **4** (especially if `doctor` says `this_device_is_recipient: error`) —
   re-bootstrapping involves the recovery passphrase.
2. `token_scope` (exit 8) blocks an entry you genuinely need — widening access is a human
   decision.
3. You can't tell which side of a conflict is correct — guessing swaps a production key for a dead one.
4. You're about to `rm --purge` or `export` — both are irreversible or cross a boundary.

Everything else you should be able to resolve yourself from `schema`, the exit code, and `list`.