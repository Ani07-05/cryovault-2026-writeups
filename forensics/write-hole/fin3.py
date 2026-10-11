exec(open('fin2.py').read().split("out=b''")[0])
i=3
s,dd,od,pd=disks(base+i)
a=chunk(dd,s);b=xor(chunk(od,s),chunk(pd,s))
print('disks data,other,parity',dd,od,pd)
for j in range(64):
    x=a[j*512:(j+1)*512];y=b[j*512:(j+1)*512]
    print(j,'same' if x==y else 'diff', 'a0' if not any(x) else '', 'b0' if not any(y) else '') if j%8==0 or x!=y else None
print(a[:40].hex());print(b[:40].hex())
# rec4 chunk and parity relation
c4=chunk(od,s);p=chunk(pd,s)
print('data3 xor data4 == parity?',xor(a,c4)==p)
