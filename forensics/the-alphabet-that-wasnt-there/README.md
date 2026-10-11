# The Alphabet That Wasn't There -- Forensics

**Flag:** `isfcr{d7ef3d5dd98bd325c3b50114}`
**Tools:** Python, custom PDF content-stream interpreter (incremental-update/xref walking,
Form XObject + bitmap-glyph rendering), scrypt + AES-GCM
**Scripts:** `cand.py` is the verbatim final decrypt driver, recovered from the session
transcript with the real crypto constants intact. The custom PDF renderer it imports
(`solve.py` / `Doc`/`Renderer`/`GS`/`Ref` etc.) was **not** present in the retrieved
transcript pages, so this one is not runnable standalone -- see below for exactly what's
missing and what that renderer had to do.

`cand.py` here is the **verbatim final driver script** pulled from the
session transcript, with the real crypto constants (CaseID, scrypt salt,
AES-GCM nonce/ciphertext/AAD) intact — running `tryg(grid)` with the correct
256-glyph grid string reproduces the flag:

```
isfcr{d7ef3d5dd98bd325c3b50114}
```

**What's NOT recovered verbatim:** `cand.py` does `from solve import *`,
pulling in a custom PDF content-stream interpreter (`Doc`, `Renderer`, `GS`,
`Ref`, plus helpers `refmap`, `font_unit`, `bitmap`, `glyph_rects`, `canon`,
and `numpy as np`) that the session built up earlier and incrementally while
exploring `damaged.pdf`. That module's source wasn't present in the
transcript pages this writeup was built from, so this driver isn't
runnable standalone — you'd need to re-implement that renderer against
`damaged.pdf` / `reference.pdf` from this challenge to actually reproduce
the grid string and feed it to `tryg()`.

What the renderer had to do (per the transcript):
- Walk the PDF's incremental-update chain by hand to find a **third,
  unreferenced revision** (no xref entry) with its own CaseID
  (`9697624543591457a15dc6d9a4797c45`) — the real target, not the two
  "proper" revisions a normal reader would open.
- Interpret that revision's content stream: 99 nested Form XObjects,
  `/Rotate 90` (ignored, per the task), BBox/`W n` clipping, and `Tr 3`
  (invisible-text) rendering mode, to determine which of the glyphs on a
  16x16 lattice are genuinely visible (256 of them).
- Match each visible glyph to `reference.pdf`'s labelled alphabet via
  rotation-normalised bitmap comparison (mirrors count as distinct symbols).
- **Key pitfall:** 14 "white patch" overlay Form XObjects sit on top of
  some grid glyphs. Reading the grid *with* those overlays respected gives
  a plausible-but-wrong string that always fails the scrypt/AES-GCM decrypt
  (`cryptography.exceptions.InvalidTag`). Dropping the overlays and reading
  the original 256 lattice glyphs underneath is what actually decrypts.
