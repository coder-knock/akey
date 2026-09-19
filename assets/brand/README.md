# Brand assets

The akey identity, as PNG. Nothing here is generated at build time — these files are the source of
truth, so copy them rather than re-deriving them from the site or the README.

| File | Size | Use |
|---|---|---|
| `logo-dark-1200.png` | 1200×1200 | Stacked lockup, dark background (`#0B1220`) |
| `logo-light-1200.png` | 1200×1200 | Stacked lockup, light background (`#F8FAFC`) |
| `logo-horizontal-dark-1600x480.png` | 1600×480 | Horizontal lockup for dark surfaces |
| `logo-horizontal-light-1600x480.png` | 1600×480 | Horizontal lockup for light surfaces |
| `icon-dark-1024.png` | 1024×1024 | Mark on `#0B1220` |
| `icon-light-1024.png` | 1024×1024 | Mark on `#F8FAFC` |
| `icon-transparent-1024.png` | 1024×1024 | Mark with a real alpha channel — the one to use on a surface you control |
| `app-icon-512.png` | 512×512 | macOS / iOS / store icon |
| `favicon-32.png` | 32×32 | Favicon |
| `github-banner-1600x500.png` | 1600×500 | The banner at the top of both READMEs |

## Marks

The mark is three things at once:

- **A** — the project's initial, and the "A" in *agent*.
- **Keyhole** — the point of the product: an agent can use a secret without ever seeing the
  plaintext. It sits in the counter of the A, so the letter cannot be read without it.
- **Ring of nodes** — the AI ecosystem around the vault: agents, tools, MCP servers, integrations.
  The two arcs are open, because the vault is what closes them.

The letterform is angular, not rounded — square-cut terminals, a sharp chevron, straight-edged
legs. Do not apply a corner radius, and do not re-draw the mark with rounded caps.

## Colour

Sampled from `icon-transparent-1024.png`; a single icon contains almost nothing else.

| Token | Value | Role |
|---|---|---|
| Deep navy | `#0B1220` | Dark background |
| Primary blue | `#2563EB` | The letterform — trust, technical |
| Cyan | `#06B6D4` | Structure and connections |
| Light cyan | `#22D3EE` | The chevron and node ring — innovation |
| Light surface | `#F8FAFC` | Light background, and the keyhole |

The keyhole is `#F8FAFC`, not `#FFFFFF`. Keep it that way — on a light surface the mark is carried
by the blue and cyan, and a pure-white keyhole would disappear.

## Type

Wordmark and tagline: **Inter**, or a close neutral grotesque. The tagline is monospaced and
letter-spaced. Both are baked into the lockup PNGs — do not try to re-set them, and do not
substitute a different sans.

Tagline, verbatim: `agent-safe credential vault`

## Rules

1. **Use the supplied files as-is.** Do not recolour the letterform, add gradients, outlines, or
   drop shadows, and do not place the mark on a busy photograph.
2. **Pick the variant for the surface.** `-dark` on dark, `-light` on light, `-transparent` when
   you set the surface yourself. Do not put a light-background asset on a dark page.
3. **Keep the clear space.** Leave at least the width of the keyhole's head free on every side.
   Nothing should enter the ring.
4. **Do not stretch.** Scale proportionally only.
5. **The mark is not a lock icon.** Do not extract the keyhole for use on its own — that reads as
   a generic padlock and drops the A and the node ring that carry the meaning.
