b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
needles=[b"checkFlag_v1_LEGACY",b"checkFlag_v2",b"finalizeFlag",b"com.silvergate.vault.LockActivity",b"isfcr{%016llx}",b"checkFlag_v2 entered",b"dev_overlay_do_not_submit",b"preprod_token_v3",b"dex\n035\x00",b"ART-OPT",b"oat.image.location",b"ARM64-A75",b"android.boot.image.art.token",b"art.compiler.filter",b"compiled by art-opt"]
for n in needles:
    i=b.find(n)
    print(hex(i) if i>=0 else "NOTFOUND", i, n)
print("total len", len(b), hex(len(b)))
