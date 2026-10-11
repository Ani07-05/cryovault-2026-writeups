# The Meridian -- Web

**Flag:** `isfcr{d33p_m3rg3_p0llut3s_th3_pr0v3n4nc3_v4ult_1n_th3_m3r1d14n}`
**Tools:** curl, xh, Node.js (source review + offline PoC of the merge chain), Python (offline key derivation)
**Scripts:** `derive_key.py` is a reconstruction of the original `decode.js`/`verify.js`/`vaultopen.js`
(same derivation, re-expressed in Python).

## Enumeration

Service at `isfcrpesu-the-meridian.chals.io` -- a 14-print photo-provenance "museum", with one hidden
negative gated behind a `vault.openVault()` call.

```
$ xh -h GET https://isfcrpesu-the-meridian.chals.io
$ curl -s https://isfcrpesu-the-meridian.chals.io
```

Pulled every client asset for source review: `assets/css/meridian.css`, `vendor/mcrypto.js`,
`assets/js/core.js`, `data/meridian-data.js`, `assets/js/legacy/provenance.js`, etc.

## Analysis

`core.js` runs a regex `BLOCK` filter on shared-link JSON text for the literal substrings
`__proto__`/`constructor`/`prototype` -- but that filter runs on the raw string, *before* `JSON.parse`
decodes unicode escapes. So `__proto__` sails through the regex and becomes the real
key `__proto__` once parsed, letting a `deepMerge` call pollute `Object.prototype`.

`sanitizeConfig()` only deletes `cfg.vault` as an *own* property -- an inherited (polluted) `vault`
descriptor survives that cleanup, so `Core.openVault()` ends up reading an attacker-controlled `vault`
object straight off the prototype.

## Exploit

```
$ node decode.js     # confirm the __proto__ JSON-escape bypass locally
$ node verify.js     # derive curators + rounds offline against the v3 pepper
$ node vaultopen.js  # confirm the derived key decrypts the sealed negative
```

The vault needs a `{curators, rounds}` descriptor: `curators` = the curator of every exhibit whose `sig`
verifies against the *current* pepper (`meridian::provenance::v3::do-not-share` -- not the v2 badge
check most of the UI still uses), taken in accession order: `E. Vantar, R. Oikawa, H. Delacroix,
K. Adeyemi, S. Marchetti`. `rounds = 1000 + (sum of exhibit years mod 4096) = 2767`.

`key = SHA-256 iterated 2767 times over bsalt + ":" + curators.join("|")`; that key decrypts the AES-GCM
blob holding the hidden negative's caption -- the flag -- verified fully offline, no need to actually
drive the prototype-pollution PoC through the live browser session to read it out.

A decoy, `isfcr{l3g4cy_st4ff_c0ns0l3_1s_n0t_th3_v4ult}`, sits behind an unrelated legacy console and the
in-app journal explicitly calls it out as not the vault key.

## Flag

`isfcr{d33p_m3rg3_p0llut3s_th3_pr0v3n4nc3_v4ult_1n_th3_m3r1d14n}`
