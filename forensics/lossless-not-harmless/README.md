# Lossless, Not Harmless -- Forensics

**Flag:** `isfcr{ch0ic3s_th3_d3c0d3r_n3v3r_s33s}`
**Tools:** Python 3 (from-scratch DEFLATE token decoder), hashlib, hmac
**Scripts:** `deflate_tokens.py` is the verified DEFLATE token decoder (byte-exact against
`zlib.decompress`), recovered from the session scratchpad. `ties.py` is the earlier
ambiguous-match-tie collector that turned out to be a dead end (kept for reference). The final
key/ciphertext extraction and decrypt step was rebuilt from scratch in a later session rather than
recovered as a standalone file -- see the method below.

## Enumeration

Given `mosaic_0417.png`, a 256x300 8-bit palette PNG. "An archive server re-compresses every image
that comes through it with its own in-house compressor. One picture that passed through is hiding a
message." The PNG's `Software` tEXt tag reads `dfl-stitch 2.3 (equivalent-match mode, flush=sync)` --
a custom deflate-level re-encoder, strongly implying the hidden channel lives in *compression choices*
rather than pixel values.

## Decoys found (confirmed, not the flag)

1. **`Comment` tEXt chunk**, base64-decoded: `isfcr{nope_not_this_one}`
2. **Pixel-index LSB plane** (palette index bit 0 of all 76800 pixels, row-major, MSB-first byte
   packing): `isfcr{lsb_is_the_first_place_everyone_looks}`
3. **"560 suboptimal matches" lead** -- an earlier read of non-maximum-length matches as a side
   channel. Dead end: every match in the real stream is already maximum-length, so there's nothing
   to read there.

Both tEXt decoys explicitly taunt that they aren't it, and the `Software` tag points at something
deeper in the compressor's behavior -- which turned out to be two separate, independent channels in
the same stream.

## Analysis

Wrote a full DEFLATE decoder (`deflate_tokens.py`, verified byte-exact against `zlib.decompress`)
that tracks the literal/length/distance *token stream*, not just the expanded bytes. The real
hidden data turned out to live in two places at once, both of which the decompressed pixel bytes
never show:

1. **The key is in the sync-flush padding bits.** The compressor writes a zero-length stored block
   (a sync flush) every 125 tokens -- 31 of them total. Each one has non-zero padding bits between
   its header and the next byte boundary (real zlib would always write zero padding there, so this
   is deliberate). Joined in stream order, MSB-first, those are exactly 128 bits (16 bytes) of key:
   `2814c69217b303ec00c6280fa2c50286`.
2. **The ciphertext is in the equal-length-match distance choices.** Every match is already
   maximum length, so match length carries no signal. But at 3,528 positions, the set of
   equally-valid distances for that maximum-length match includes both odd and even values -- the
   parity of the one distance the compressor actually picked is one bit of signal. Packed
   MSB-first, those 3,528 bits decode to a `DFL8`-tagged blob containing a plaintext description of
   its own scheme (`ks_i = SHA256(key|nonce|u32be(i))`, `ct = pt ^ ks`, plus an 8-byte
   HMAC-SHA256 tag) followed by the actual ciphertext.

The earlier "560 suboptimal matches" and plain nearest/farthest/rank tie-break readings were all
dead ends -- the real signal is specifically the *parity* of the chosen distance, only among
positions where both parities were available, not the ambiguous-tie set as a whole.

## Exploit

1. Decode the full token stream with `deflate_tokens.py`.
2. Collect the 128 non-zero sync-flush padding bits (stream order, MSB-first) -> the 16-byte key.
3. Collect the distance-parity bit at each of the 3,528 odd/even-ambiguous match positions
   (MSB-first) -> the `DFL8` blob, which self-describes the cipher and carries
   `nonce(8) || ciphertext(37) || tag(8)`.
4. Derive the keystream `ks_i = SHA256(key || nonce || u32be(i))` per output byte, XOR it with the
   ciphertext to recover the plaintext, and verify the 8-byte HMAC-SHA256 tag against the 16-byte
   key before trusting the result.

## Verification

The HMAC-SHA256 tag on the decrypted blob verified against the recovered 16-byte key, confirming
this is the real payload and not a third decoy. (One parsing detail: the blob's length framing is
off by one from a naive read of the `\x00\x29` stored-block header -- the real 53-byte window
(8-byte nonce, 37-byte ciphertext, 8-byte tag) starts one byte after where that header appears to
end.)

## Files

- `deflate_tokens.py` -- the verified DEFLATE token decoder (reusable for any further analysis).
- `ties.py` -- the ambiguous-match-tie collector/binary-encoder from the first pass; superseded by
  the parity-of-chosen-distance reading above, kept here since it's still useful for exploring the
  token stream.
