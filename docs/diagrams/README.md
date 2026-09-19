# Diagrams

Three diagrams, each in English and Chinese. Every figure is generated from the JSON spec beside
it, so nothing here is hand-drawn — edit the spec and regenerate.

| Figure | English | 中文 |
|---|---|---|
| Architecture | [`akey-architecture.en.html`](akey-architecture.en.html) | [`akey-architecture.zh-CN.html`](akey-architecture.zh-CN.html) |
| Sync workflow | [`akey-sync-workflow.en.html`](akey-sync-workflow.en.html) | [`akey-sync-workflow.zh-CN.html`](akey-sync-workflow.zh-CN.html) |
| Run sequence | [`akey-run-sequence.en.html`](akey-run-sequence.en.html) | [`akey-run-sequence.zh-CN.html`](akey-run-sequence.zh-CN.html) |

## What each one shows

**Architecture** — components and the two trust boundaries: what lives in `$AKEY_HOME` and never
enters git, versus what leaves the machine as ciphertext. The return path from the child process
through the masker is drawn explicitly.

**Sync workflow** — `akey sync` across two machines, as four lanes and three phases, with the three
convergence paths kept apart and the revocation guard placed before `reset --hard`.

**Run sequence** — `akey run` message by message, including the two orderings that are
load-bearing: authorization before decryption, and masking before anything reaches the caller.

## Reading them

Each `.html` file is standalone — no server, no build step, no network. Open it in a browser for
pan, zoom, search, relationship tracing, semantic views, presentation mode, dark/light switching,
and PNG / SVG / WebM export.

The `.png` files are the same figures rendered for embedding in Markdown, where HTML cannot be
shown inline. They are produced from the HTML, not authored separately.

## Regenerating

The diagrams are built with [Archify](https://github.com/tt-a1i/archify) (MIT). With its skill
installed, from the repository root:

```bash
# validate, then build the standalone HTML
node "$ARCHIFY/bin/archify.mjs" validate architecture docs/diagrams/akey-architecture.en.json --quality showcase --json
node "$ARCHIFY/bin/archify.mjs" deliver  architecture docs/diagrams/akey-architecture.en.json docs/diagrams/akey-architecture.en.html --quality showcase --json
```

`deliver` is the acceptance command, not `render`: a non-zero exit is a failed figure, and the
previous output is left untouched. All six currently pass with 9 of 9 artifact checks,
0 errors and 0 warnings.

The `.png` previews are an element screenshot of the figure's `<svg>` in a real browser, forced to
the light theme with the viewer's control bar hidden — the control bar is page chrome, not part of
the figure.

## Notes on the specs

- `meta.locale` is `en` or `zh-CN` and controls the viewer's own UI language. It never translates
  authored content, which is why each language needs its own spec.
- The English architecture spec authors the same geometry as the Chinese one, but shortens several
  sublabels. The renderer shrinks node text to fit, and a long English sublabel pushes the
  projected font below the 6px legibility floor at a 1440px viewport. Shortening the copy is the
  right repair; shrinking the type is not.
- `akey-*.visual-check.*` files are regenerable verification sidecars (measurements and
  screenshots) and are gitignored.
