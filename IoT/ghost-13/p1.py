import struct,pickle
d=open('plc_traffic.pcap','rb').read()
o=24; segs=[]
while o<len(d):
    ts,tu,cl,ol=struct.unpack('<IIII',d[o:o+16]); k=d[o+16:o+16+cl]; o+=16+cl
    ip=k[14:]; ihl=(ip[0]&15)*4; t=ip[ihl:]
    sp,dp,seq,ack=struct.unpack('>HHII',t[:12]); off=(t[12]>>4)*4
    if dp==502: segs.append((sp,seq,t[off:]))
for port in (49152,49153):
    st={}
    for sp,seq,pl in segs:
        if sp==port and pl:
            st[seq]=pl
    base=min(st) ; buf=bytearray()
    for seq in sorted(st):
        if seq-base<len(buf): print('overlap',seq) 
        buf+=st[seq]
    print(port,len(buf))
    pos=0
    while pos<len(buf):
        tid,pid,ln,uid=struct.unpack('>HHHB',buf[pos:pos+7])
        pdu=buf[pos+7:pos+6+ln]
        print(' mbap',tid,ln,uid,pdu[:7].hex(), len(pdu), pdu[7:].hex() if len(pdu)>7 else '')
        pos+=6+ln
