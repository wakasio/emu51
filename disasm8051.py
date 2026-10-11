#!/usr/bin/env python3
"""Minimal but complete MCS-51 (8051) disassembler for firmware RE.
Usage: disasm8051.py <file> <start_hex> <len_hex> [base_hex]
Importable: decode(data, off) -> (length, text, flow) ; disasm(data, start, length, base).
flow = ('jmp'|'call'|'cjmp'|'ret'|None, target_or_None)
Addresses are 16-bit code addresses (base + offset within a 64K bank).
"""
import sys

SFR = {0x80:'P0',0x81:'SP',0x82:'DPL',0x83:'DPH',0x87:'PCON',0x88:'TCON',0x89:'TMOD',
0x8A:'TL0',0x8B:'TL1',0x8C:'TH0',0x8D:'TH1',0x90:'P1',0x98:'SCON',0x99:'SBUF',
0xA0:'P2',0xA8:'IE',0xB0:'P3',0xB8:'IP',0xD0:'PSW',0xE0:'ACC',0xF0:'B'}

def dname(a):
    return SFR.get(a, "0x%02X"%a)

def bitname(b):
    byte = 0x20 + (b>>3) if b<0x80 else (b & 0xF8)
    bit = b & 7
    base = dname(byte) if b>=0x80 else "0x%02X"%byte
    return "%s.%d"%(base,bit)

def decode(d, off):
    """Return (length, text, (flowtype,target))."""
    op = d[off]
    hi, lo = op>>4, op&0xF
    b1 = d[off+1] if off+1<len(d) else 0
    b2 = d[off+2] if off+2<len(d) else 0
    def rel(r, l):
        return (off_base + off + l + ((r^0x80)-0x80)) & 0xFFFF
    # off_base maps file offset -> code addr; set by disasm(); default 0
    global off_base
    # --- regular Rn / @Ri groups by low nibble 6..F ---
    if lo>=0x8:
        rn = lo-0x8
        grp = {0x0:('INC R%d',1,None),0x1:('DEC R%d',1,None),0x2:('ADD A,R%d',1,None),
               0x3:('ADDC A,R%d',1,None),0x4:('ORL A,R%d',1,None),0x5:('ANL A,R%d',1,None),
               0x6:('XRL A,R%d',1,None),0x7:('MOV R%d,#0x%02X',2,None),0x8:('MOV 0x%02X,R%d',2,None),
               0x9:('SUBB A,R%d',1,None),0xA:('MOV R%d,0x%02X',2,None),0xB:('CJNE R%d,#0x%02X,',3,'cjmp'),
               0xC:('XCH A,R%d',1,None),0xD:('DJNZ R%d,',2,'cjmp'),0xE:('MOV A,R%d',1,None),0xF:('MOV R%d,A',1,None)}
        m,l,fl = grp[hi]
        if hi==0x7: return l,("MOV R%d,#0x%02X"%(rn,b1)),(None,None)
        if hi==0x8: return l,("MOV %s,R%d"%(dname(b1),rn)),(None,None)
        if hi==0xA: return l,("MOV R%d,%s"%(rn,dname(b1))),(None,None)
        if hi==0xB: t=rel(b2,3); return 3,("CJNE R%d,#0x%02X,0x%04X"%(rn,b1,t)),('cjmp',t)
        if hi==0xD: t=rel(b1,2); return 2,("DJNZ R%d,0x%04X"%(rn,t)),('cjmp',t)
        return l,(m%rn),(None,None)
    if lo in (0x6,0x7):
        ri = lo-0x6
        if hi==0x0: return 1,("INC @R%d"%ri),(None,None)
        if hi==0x1: return 1,("DEC @R%d"%ri),(None,None)
        if hi==0x2: return 1,("ADD A,@R%d"%ri),(None,None)
        if hi==0x3: return 1,("ADDC A,@R%d"%ri),(None,None)
        if hi==0x4: return 1,("ORL A,@R%d"%ri),(None,None)
        if hi==0x5: return 1,("ANL A,@R%d"%ri),(None,None)
        if hi==0x6: return 1,("XRL A,@R%d"%ri),(None,None)
        if hi==0x7: return 2,("MOV @R%d,#0x%02X"%(ri,b1)),(None,None)
        if hi==0x8: return 2,("MOV %s,@R%d"%(dname(b1),ri)),(None,None)
        if hi==0x9: return 1,("SUBB A,@R%d"%ri),(None,None)
        if hi==0xA: return 2,("MOV @R%d,%s"%(ri,dname(b1))),(None,None)
        if hi==0xB: t=rel(b2,3); return 3,("CJNE @R%d,#0x%02X,0x%04X"%(ri,b1,t)),('cjmp',t)
        if hi==0xC: return 1,("XCH A,@R%d"%ri),(None,None)
        if hi==0xD: return 1,("XCHD A,@R%d"%ri),(None,None)
        if hi==0xE: return 1,("MOV A,@R%d"%ri),(None,None)
        if hi==0xF: return 1,("MOV @R%d,A"%ri),(None,None)
    # --- low nibble 1: AJMP/ACALL (addr11) ---
    if lo==0x1:
        t = ((off_base+off+2)&0xF800) | ((op&0xE0)<<3) | b1
        if hi%2==0: return 2,("AJMP 0x%04X"%t),('jmp',t)
        else:       return 2,("ACALL 0x%04X"%t),('call',t)
    # --- column 0 ---
    if lo==0x0:
        if op==0x00: return 1,"NOP",(None,None)
        if op==0x10: t=rel(b2,3); return 3,("JBC %s,0x%04X"%(bitname(b1),t)),('cjmp',t)
        if op==0x20: t=rel(b2,3); return 3,("JB %s,0x%04X"%(bitname(b1),t)),('cjmp',t)
        if op==0x30: t=rel(b2,3); return 3,("JNB %s,0x%04X"%(bitname(b1),t)),('cjmp',t)
        if op==0x40: t=rel(b1,2); return 2,("JC 0x%04X"%t),('cjmp',t)
        if op==0x50: t=rel(b1,2); return 2,("JNC 0x%04X"%t),('cjmp',t)
        if op==0x60: t=rel(b1,2); return 2,("JZ 0x%04X"%t),('cjmp',t)
        if op==0x70: t=rel(b1,2); return 2,("JNZ 0x%04X"%t),('cjmp',t)
        if op==0x80: t=rel(b1,2); return 2,("SJMP 0x%04X"%t),('jmp',t)
        if op==0x90: return 3,("MOV DPTR,#0x%04X"%((b1<<8)|b2)),(None,None)
        if op==0xA0: return 2,("ORL C,/%s"%bitname(b1)),(None,None)
        if op==0xB0: return 2,("ANL C,/%s"%bitname(b1)),(None,None)
        if op==0xC0: return 2,("PUSH %s"%dname(b1)),(None,None)
        if op==0xD0: return 2,("POP %s"%dname(b1)),(None,None)
        if op==0xE0: return 1,"MOVX A,@DPTR",(None,None)
        if op==0xF0: return 1,"MOVX @DPTR,A",(None,None)
    # --- column 2 ---
    if lo==0x2:
        if op==0x02: t=(b1<<8)|b2; return 3,("LJMP 0x%04X"%t),('jmp',t)
        if op==0x12: t=(b1<<8)|b2; return 3,("LCALL 0x%04X"%t),('call',t)
        if op==0x22: return 1,"RET",('ret',None)
        if op==0x32: return 1,"RETI",('ret',None)
        if op==0x42: return 2,("ORL %s,A"%dname(b1)),(None,None)
        if op==0x52: return 2,("ANL %s,A"%dname(b1)),(None,None)
        if op==0x62: return 2,("XRL %s,A"%dname(b1)),(None,None)
        if op==0x72: return 2,("ORL C,%s"%bitname(b1)),(None,None)
        if op==0x82: return 2,("ANL C,%s"%bitname(b1)),(None,None)
        if op==0x92: return 2,("MOV %s,C"%bitname(b1)),(None,None)
        if op==0xA2: return 2,("MOV C,%s"%bitname(b1)),(None,None)
        if op==0xB2: return 2,("CPL %s"%bitname(b1)),(None,None)
        if op==0xC2: return 2,("CLR %s"%bitname(b1)),(None,None)
        if op==0xD2: return 2,("SETB %s"%bitname(b1)),(None,None)
        if op==0xE2: return 1,"MOVX A,@R0",(None,None)
        if op==0xF2: return 1,"MOVX @R0,A",(None,None)
    # --- column 3 ---
    if lo==0x3:
        if op==0x03: return 1,"RR A",(None,None)
        if op==0x13: return 1,"RRC A",(None,None)
        if op==0x23: return 1,"RL A",(None,None)
        if op==0x33: return 1,"RLC A",(None,None)
        if op==0x43: return 3,("ORL %s,#0x%02X"%(dname(b1),b2)),(None,None)
        if op==0x53: return 3,("ANL %s,#0x%02X"%(dname(b1),b2)),(None,None)
        if op==0x63: return 3,("XRL %s,#0x%02X"%(dname(b1),b2)),(None,None)
        if op==0x73: return 1,"JMP @A+DPTR",('jmp',None)
        if op==0x83: return 1,"MOVC A,@A+PC",(None,None)
        if op==0x93: return 1,"MOVC A,@A+DPTR",(None,None)
        if op==0xA3: return 1,"INC DPTR",(None,None)
        if op==0xB3: return 1,"CPL C",(None,None)
        if op==0xC3: return 1,"CLR C",(None,None)
        if op==0xD3: return 1,"SETB C",(None,None)
        if op==0xE3: return 1,"MOVX A,@R1",(None,None)
        if op==0xF3: return 1,"MOVX @R1,A",(None,None)
    # --- column 4 ---
    if lo==0x4:
        if op==0x04: return 1,"INC A",(None,None)
        if op==0x14: return 1,"DEC A",(None,None)
        if op==0x24: return 2,("ADD A,#0x%02X"%b1),(None,None)
        if op==0x34: return 2,("ADDC A,#0x%02X"%b1),(None,None)
        if op==0x44: return 2,("ORL A,#0x%02X"%b1),(None,None)
        if op==0x54: return 2,("ANL A,#0x%02X"%b1),(None,None)
        if op==0x64: return 2,("XRL A,#0x%02X"%b1),(None,None)
        if op==0x74: return 2,("MOV A,#0x%02X"%b1),(None,None)
        if op==0x84: return 1,"DIV AB",(None,None)
        if op==0x94: return 2,("SUBB A,#0x%02X"%b1),(None,None)
        if op==0xA4: return 1,"MUL AB",(None,None)
        if op==0xB4: t=rel(b2,3); return 3,("CJNE A,#0x%02X,0x%04X"%(b1,t)),('cjmp',t)
        if op==0xC4: return 1,"SWAP A",(None,None)
        if op==0xD4: return 1,"DA A",(None,None)
        if op==0xE4: return 1,"CLR A",(None,None)
        if op==0xF4: return 1,"CPL A",(None,None)
    # --- column 5 ---
    if lo==0x5:
        if op==0x05: return 2,("INC %s"%dname(b1)),(None,None)
        if op==0x15: return 2,("DEC %s"%dname(b1)),(None,None)
        if op==0x25: return 2,("ADD A,%s"%dname(b1)),(None,None)
        if op==0x35: return 2,("ADDC A,%s"%dname(b1)),(None,None)
        if op==0x45: return 2,("ORL A,%s"%dname(b1)),(None,None)
        if op==0x55: return 2,("ANL A,%s"%dname(b1)),(None,None)
        if op==0x65: return 2,("XRL A,%s"%dname(b1)),(None,None)
        if op==0x75: return 3,("MOV %s,#0x%02X"%(dname(b1),b2)),(None,None)
        if op==0x85: return 3,("MOV %s,%s"%(dname(b2),dname(b1))),(None,None)
        if op==0x95: return 2,("SUBB A,%s"%dname(b1)),(None,None)
        if op==0xA5: return 1,"?A5",(None,None)
        if op==0xB5: t=rel(b2,3); return 3,("CJNE A,%s,0x%04X"%(dname(b1),t)),('cjmp',t)
        if op==0xC5: return 2,("XCH A,%s"%dname(b1)),(None,None)
        if op==0xD5: t=rel(b2,3); return 3,("DJNZ %s,0x%04X"%(dname(b1),t)),('cjmp',t)
        if op==0xE5: return 2,("MOV A,%s"%dname(b1)),(None,None)
        if op==0xF5: return 2,("MOV %s,A"%dname(b1)),(None,None)
    return 1,("DB 0x%02X"%op),(None,None)

off_base = 0
def disasm(d, start, length, base=0):
    global off_base
    off_base = base - start   # so code_addr = base + (off-start) = off + off_base
    out=[]
    off=start; end=start+length
    while off<end:
        l,text,flow = decode(d, off)
        raw=' '.join('%02X'%d[off+i] for i in range(l))
        addr=(off+off_base)&0xFFFF
        out.append("%04X: %-14s %s"%(addr,raw,text))
        off+=l
    return '\n'.join(out)

if __name__=='__main__':
    f=sys.argv[1]; start=int(sys.argv[2],16); length=int(sys.argv[3],16)
    base=int(sys.argv[4],16) if len(sys.argv)>4 else start
    d=open(f,'rb').read()
    print(disasm(d,start,length,base))
