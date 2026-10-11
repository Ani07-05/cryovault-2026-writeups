from Crypto.Cipher import AES

nwkkey = bytes.fromhex("ffa0be732cd8f56eae8caa21359baf06")

def nonce_aad(eui_le_hex, fc, sec_ctl=0x05):
    eui_le = bytes.fromhex(eui_le_hex)
    eui_be = eui_le[::-1]
    nonce = eui_be + fc.to_bytes(4,"little") + bytes([sec_ctl])
    aad = bytes([sec_ctl]) + fc.to_bytes(4,"little") + eui_le
    return nonce, aad

eui="4000aa25004b1200"; fc=3501
ct=bytes.fromhex("bb6ba385d9752ee4ad9786702f05b53dd3c76a01bdeda3b881778716fd0e3235860e0f56d46783e6e0a2fae81d0dc739e6ee24945c442468e2cb")
mic=bytes.fromhex("58a89c4f")
nonce,aad = nonce_aad(eui,fc)
print("nonce",nonce.hex(),"aad",aad.hex(),"ctlen",len(ct))
c=AES.new(nwkkey, AES.MODE_CCM, nonce=nonce, mac_len=4)
c.update(aad)
try:
    pt = c.decrypt_and_verify(ct, mic)
    print("PLAINTEXT:", pt.hex())
    cluster=int.from_bytes(pt[0:2],"little")
    attr=int.from_bytes(pt[2:4],"little")
    vlen=int.from_bytes(pt[4:6],"little")
    value=pt[6:6+vlen]
    print("cluster",hex(cluster),"attr",hex(attr),"vlen",vlen,"value",value)
except Exception as e:
    print("fail",e)
