from Crypto.Cipher import AES

tclinkkey = bytes.fromhex("7cf8b0b78be9f36a225c1e70692e1e1c")

def nonce_aad(eui_le_hex, fc, sec_ctl=0x05):
    eui_le = bytes.fromhex(eui_le_hex)
    eui_be = eui_le[::-1]
    nonce = eui_be + fc.to_bytes(4,"little") + bytes([sec_ctl])
    aad = bytes([sec_ctl]) + fc.to_bytes(4,"little") + eui_le
    return nonce, aad

# TRANSPORT_KEY packet 39
eui="0100aa25004b1200"; fc=100
ct=bytes.fromhex("516193f8b8e2fd2a41acb21f8ef850a4")
mic=bytes.fromhex("e85b1ffe")
nonce,aad = nonce_aad(eui,fc)
print("nonce",nonce.hex(),"aad",aad.hex())
c=AES.new(tclinkkey, AES.MODE_CCM, nonce=nonce, mac_len=4)
c.update(aad)
try:
    pt = c.decrypt_and_verify(ct, mic)
    print("NWK KEY:", pt.hex())
except Exception as e:
    print("fail",e)
