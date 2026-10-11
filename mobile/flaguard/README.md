# FlaGuard -- Mobile

**Tools:** unzip/apktool, Python, openssl (manual AES-CBC key/IV derivation), androguard, Android emulator (AVD)
**Scripts:** Original scripts recovered from the session scratchpad: `dec.py`.
**Flag:** `isfcr{sh4d0w_cl455l04d3r_tr1ckery}` (see note below)

## Enumeration

flaguard.apk: pitched as "the strictest flag-format validator around." Unpacked the APK into its own directory and pulled strings from classes.dex and the asset files.

## Analysis

App.attachBaseContext() runs bind(), which decrypts assets/theme.pack (AES-256-CBC, no padding) into a second, hidden DEX. Key = SHA256(palette.webp[off:off+128] || "flaguard-boot-v3" || SHA256(classes.dex)), where off = (palette.webp[16] & 0x3f) + 64; IV = SHA256(SHA256(classes.dex) || block[:16])[:16]; strings come from a Veil XOR-0x5b string table. bind() loads the hidden DEX through an InMemoryDexClassLoader and sets it as the parent of the app's classloader -- Android resolves parent classes first, so the hidden FlagChecker silently replaces the one visible in classes.dex. (A ".internal"/trust.chain branch only triggers for package names ending in .internal; this app is dev.srspace.flaguard, so it never fires.)
First attempt solved that hidden checker's rolling-XOR scheme statically (in[i] = T[i] ^ M[i] ^ k, k ^= in[i], k0=90) and got isfcr{p4r3nt_f1rst_d3x_1s_s0_m34n} -- this was WRONG when actually submitted, because the visible, decoy FlagChecker in classes.dex is the one CTFd actually grades against here, not the hidden one.

## Exploit

Switched to the visible FlagChecker in classes.dex and reversed its real check: a rolling hash where h = (h*131 + byte + P[i % 6]) & 0xffff must equal the stored constant C[i] at every input position (P is a fixed 6-byte key schedule embedded in the class). Solved for the input byte-by-byte against that recurrence; the recovered string is the shadow classloader trick's own name, submitted as the flag.

## Verification

Confirmed correct after submission (the first, hidden-DEX-derived candidate was rejected).
