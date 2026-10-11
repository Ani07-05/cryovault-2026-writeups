import capstone
b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
blob=b[0x290:0x1899]
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for shift in range(4):
    data=blob[shift:]
    count=0; total=0
    for i in md.disasm(data, 0x290+shift):
        count+=1
    print('shift',shift,'insns decoded',count,'out of approx',len(data)//4)
