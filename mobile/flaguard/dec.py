import hashlib,subprocess
X=r'C:\Users\Aniruddh\Downloads\flaguard_x'
A=open(X+r'\assets\palette.webp','rb').read()
h=hashlib.sha256(open(X+r'\classes.dex','rb').read()).digest()
off=(A[16]&0x3f)+64
blk=A[off:off+128]
key=hashlib.sha256(blk+b'flaguard-boot-v3'+h).digest()
iv=hashlib.sha256(h+blk[:16]).digest()[:16]
r=subprocess.run(['openssl','enc','-d','-aes-256-cbc','-nopad','-K',key.hex(),'-iv',iv.hex(),'-in',X+r'\assets\theme.pack','-out','hidden.dex'],capture_output=True)
print(r.returncode,r.stderr)
print(open('hidden.dex','rb').read()[:8])
