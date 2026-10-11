import struct
b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
off=2192
magic=b[off:off+8]
checksum=struct.unpack_from("<I",b,off+8)[0]
sha1=b[off+12:off+32]
file_size,header_size,endian_tag=struct.unpack_from("<III",b,off+32)
print(magic, hex(checksum), sha1.hex(), file_size, header_size, hex(endian_tag))
print("remaining bytes:", len(b)-off)
