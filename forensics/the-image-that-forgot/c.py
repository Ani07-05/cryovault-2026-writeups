import json,sys,hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
D=sys.argv[1]
v=json.load(open(D+'/vault.json'))
dig="sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8"
ev="deploy-9d1a1fd93d"; sid="dispatch-ac1af5608a"
for kv in ["key-e52be7cc57","key-90a623d0c2","key-d1152a17a0"]:
    aad=json.dumps([sid,kv,dig,ev],separators=(",",":")).encode()
    for ki,k in enumerate(v['keys']):
        for ni,n in enumerate(v['notes']):
            try:
                raw=bytes.fromhex(n['data']); pt=AESGCM(bytes.fromhex(k)).decrypt(bytes.fromhex(n['nonce']),raw,aad)
                print('HIT',kv,ki,ni,pt)
            except Exception: pass
