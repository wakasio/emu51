#!/usr/bin/env python3
"""emu51 - a small MCS-51 (8051) interpreter for checking optical-drive firmware patches.

It runs single routines, not a whole drive: you set up IRAM/XDATA/registers, call a function
and compare what it wrote. Typical use is differential testing (stock image vs patched image
over thousands of inputs).

What it models
  - all 255 defined opcodes, PSW flags (CY, AC, OV, P), register banks, upper IRAM via @Ri
  - code banking through a caller-supplied address map (see CPU.__init__)
  - XDATA as a dict, with optional read/write hooks for hardware registers
  - an optional model of the MediaTek arithmetic unit at XDATA 0x403B (see Divider below)
What it does not model
  - interrupts, timers, serial, real ports (P1 bank switching only if you map it yourself)
  - timing
Notes
  - SP starts at 0x07 (8051 reset value); real firmware moves it (EH33 0x9D, VAD6038 0x9B),
    so pass sp= to CPU() when running firmware code.
  - IRAM and SFRs start at 0, ports included (a real 8051 resets P0-P3 to 0xFF). MOVX @Ri uses
    P2 as the high address byte.
  - cpu.steps counts instructions since the CPU was created; call() returns the count of one call.

Example
    img = open('fw.bin', 'rb').read()
    cpu = CPU(img, code_map=lambda a: a)          # flat 64 KiB image
    cpu.x[0x8060] = 0x12                          # XDATA
    cpu.setR(7, 0x34)
    cpu.call(0x1234)                              # runs until the routine returns
    print(cpu.R(7), cpu.x.get(0x8061))
"""


def eh33_map(bank):
    """Code map for the Lite-On EH33 / DH-16D2S layout: common 0x0000-0x3FFF at file 0x4000,
    bank n 0x4000-0xFFFF at file 0x8000 + n * 0xC000."""
    return lambda a: 0x4000 + a if a < 0x4000 else 0x8000 + bank * 0xC000 + a - 0x4000


def common64_map(bank, common_end=0x6000):
    """Code map for images stored as 64 KiB banks with the common area repeated in each
    (e.g. the Xbox 360 VAD6038): common 0..common_end-1, bank n at file n * 0x10000 + a."""
    return lambda a: a if a < common_end else bank * 0x10000 + a


class CPU:
    def __init__(self, img, code_map=None, sp=0x07):
        self.img = img
        self.code_map = code_map or (lambda a: a)
        self.iram = bytearray(256)          # 00-7F direct/indirect, 80-FF indirect only
        self.sfr = bytearray(256)           # 80-FF direct
        self.x = {}                         # XDATA
        self.xr_hook = None                 # f(cpu, addr) -> value or None (single hook)
        self.xw_hook = None                 # f(cpu, addr, value) -> True to swallow the write
        self.xr_hooks = []                  # chained hooks, see add_xr_hook / add_xw_hook
        self.xw_hooks = []
        self.pc = 0
        self.sfr[0x81] = sp
        self.steps = 0

    # ---- memory
    def code(self, a):
        f = self.code_map(a & 0xFFFF)
        if not 0 <= f < len(self.img):
            raise RuntimeError('code address %04X maps to file offset %X, outside the %d-byte image'
                               % (a & 0xFFFF, f, len(self.img)))
        return self.img[f]

    def _operand(self, a):                  # operand byte; 0 past the image end
        f = self.code_map(a & 0xFFFF)
        return self.img[f] if 0 <= f < len(self.img) else 0

    def rd(self, d):                        # direct address
        return self.iram[d] if d < 0x80 else self.sfr[d]

    def wr(self, d, v):
        if d < 0x80:
            self.iram[d] = v & 0xFF
        else:
            self.sfr[d] = v & 0xFF

    def add_xr_hook(self, f):
        """Add a read hook f(cpu, addr) -> value or None. Hooks are asked in the order added
        (then xr_hook); the first value that is not None is the result."""
        self.xr_hooks.append(f)
        return f

    def add_xw_hook(self, f):
        """Add a write hook f(cpu, addr, value) -> True to swallow the write. Every hook (and
        xw_hook) sees every write; the write reaches cpu.x unless one of them returns True."""
        self.xw_hooks.append(f)
        return f

    def xread(self, a):
        for f in self.xr_hooks + ([self.xr_hook] if self.xr_hook else []):
            r = f(self, a)
            if r is not None:
                return r & 0xFF
        return self.x.get(a, 0)

    def xwrite(self, a, v):
        v &= 0xFF
        swallow = False
        for f in self.xw_hooks + ([self.xw_hook] if self.xw_hook else []):
            swallow = bool(f(self, a, v)) or swallow
        if not swallow:
            self.x[a] = v

    def bitaddr(self, b):
        return (0x20 + (b >> 3)) if b < 0x80 else (b & 0xF8), b & 7

    def getbit(self, b):
        a, n = self.bitaddr(b)
        return (self.rd(a) >> n) & 1

    def setbit(self, b, v):
        a, n = self.bitaddr(b)
        x = self.rd(a)
        self.wr(a, (x | (1 << n)) if v else (x & ~(1 << n)))

    def push(self, v):
        self.sfr[0x81] = (self.sfr[0x81] + 1) & 0xFF
        self.iram[self.sfr[0x81]] = v & 0xFF

    def pop(self):
        v = self.iram[self.sfr[0x81]]
        self.sfr[0x81] = (self.sfr[0x81] - 1) & 0xFF
        return v

    # ---- registers
    @property
    def A(self):
        return self.sfr[0xE0]

    @A.setter
    def A(self, v):
        self.sfr[0xE0] = v & 0xFF
        self.sfr[0xD0] = (self.sfr[0xD0] & ~1) | (bin(v & 0xFF).count('1') & 1)

    @property
    def B(self):
        return self.sfr[0xF0]

    @B.setter
    def B(self, v):
        self.sfr[0xF0] = v & 0xFF

    @property
    def C(self):
        return self.sfr[0xD0] >> 7

    @C.setter
    def C(self, v):
        self.sfr[0xD0] = (self.sfr[0xD0] & 0x7F) | ((v & 1) << 7)

    @property
    def DPTR(self):
        return (self.sfr[0x83] << 8) | self.sfr[0x82]

    @DPTR.setter
    def DPTR(self, v):
        self.sfr[0x83] = (v >> 8) & 0xFF
        self.sfr[0x82] = v & 0xFF

    def _rbase(self):
        return self.sfr[0xD0] & 0x18

    def R(self, n):
        return self.iram[self._rbase() + n]

    def setR(self, n, v):
        self.iram[self._rbase() + n] = v & 0xFF

    def _psw(self, ac=None, ov=None):
        p = self.sfr[0xD0]
        if ac is not None:
            p = (p & ~0x40) | (0x40 if ac else 0)
        if ov is not None:
            p = (p & ~0x04) | (0x04 if ov else 0)
        self.sfr[0xD0] = (p & ~1) | (bin(self.A).count('1') & 1)

    def _add(self, v, c):
        a = self.A
        r = a + v + c
        self.C = r > 0xFF
        self.A = r
        self._psw(((a & 15) + (v & 15) + c) > 15, ((a ^ r) & (v ^ r) & 0x80) != 0)

    def _subb(self, v):
        a, c = self.A, self.C
        r = a - v - c
        self.C = r < 0
        self.A = r
        self._psw(((a & 15) - (v & 15) - c) < 0, ((a ^ v) & (a ^ r) & 0x80) != 0)

    # ---- execution
    def step(self):
        pc = self.pc
        op, b1, b2 = self.code(pc), self._operand(pc + 1), self._operand(pc + 2)
        hi, lo = op >> 4, op & 15
        rel = lambda r, n: (pc + n + ((r ^ 0x80) - 0x80)) & 0xFFFF
        n, npc = 1, None

        def src():                          # operand for lo 5..F: direct, @R0/@R1, R0..R7
            if lo == 5:
                return self.rd(b1)
            if lo in (6, 7):
                return self.iram[self.R(lo - 6)]
            return self.R(lo - 8)

        def dst(v):
            if lo == 5:
                self.wr(b1, v)
            elif lo in (6, 7):
                self.iram[self.R(lo - 6)] = v & 0xFF
            else:
                self.setR(lo - 8, v)

        if lo >= 5:
            n = 2 if lo == 5 else 1
        if op == 0x00:
            pass
        elif lo == 1:                                           # AJMP / ACALL
            t = ((pc + 2) & 0xF800) | ((op >> 5) << 8) | b1
            n = 2
            if hi & 1:
                self.push((pc + 2) & 0xFF); self.push((pc + 2) >> 8)
            npc = t
        elif op == 0x02:
            npc = (b1 << 8) | b2
        elif op == 0x12:
            self.push((pc + 3) & 0xFF); self.push((pc + 3) >> 8)
            npc = (b1 << 8) | b2
        elif op in (0x22, 0x32):                                # RET / RETI
            h = self.pop(); l = self.pop()
            npc = (h << 8) | l
        elif op == 0x03:
            self.A = ((self.A >> 1) | (self.A << 7))
        elif op == 0x13:
            c = self.C; self.C = self.A & 1; self.A = (self.A >> 1) | (c << 7)
        elif op == 0x23:
            self.A = ((self.A << 1) | (self.A >> 7))
        elif op == 0x33:
            c = self.C; self.C = self.A >> 7; self.A = (self.A << 1) | c
        elif op == 0x04:
            self.A += 1
        elif op == 0x14:
            self.A -= 1
        elif op == 0x05:
            self.wr(b1, self.rd(b1) + 1); n = 2
        elif op == 0x15:
            self.wr(b1, self.rd(b1) - 1); n = 2
        elif hi == 0 and lo >= 6:
            dst(src() + 1)
        elif hi == 1 and lo >= 6:
            dst(src() - 1)
        elif op in (0x10, 0x20, 0x30):                          # JBC / JB / JNB
            v = self.getbit(b1); n = 3
            if op == 0x10 and v:
                self.setbit(b1, 0)
            if (v and op != 0x30) or (not v and op == 0x30):
                npc = rel(b2, 3)
        elif op in (0x40, 0x50, 0x60, 0x70, 0x80):
            n = 2
            take = {0x40: self.C == 1, 0x50: self.C == 0, 0x60: self.A == 0, 0x70: self.A != 0, 0x80: True}[op]
            if take:
                npc = rel(b1, 2)
        elif op == 0x24:
            self._add(b1, 0); n = 2
        elif op == 0x34:
            self._add(b1, self.C); n = 2
        elif hi == 2 and lo >= 5:
            self._add(src(), 0)
        elif hi == 3 and lo >= 5:
            self._add(src(), self.C)
        elif op in (0x42, 0x52, 0x62):
            f = {0x42: lambda x: x | self.A, 0x52: lambda x: x & self.A, 0x62: lambda x: x ^ self.A}[op]
            self.wr(b1, f(self.rd(b1))); n = 2
        elif op in (0x43, 0x53, 0x63):
            f = {0x43: lambda x: x | b2, 0x53: lambda x: x & b2, 0x63: lambda x: x ^ b2}[op]
            self.wr(b1, f(self.rd(b1))); n = 3
        elif op == 0x44:
            self.A |= b1; n = 2
        elif op == 0x54:
            self.A &= b1; n = 2
        elif op == 0x64:
            self.A ^= b1; n = 2
        elif hi == 4 and lo >= 5:
            self.A |= src()
        elif hi == 5 and lo >= 5:
            self.A &= src()
        elif hi == 6 and lo >= 5:
            self.A ^= src()
        elif op == 0x72:
            self.C |= self.getbit(b1); n = 2
        elif op == 0x82:
            self.C &= self.getbit(b1); n = 2
        elif op == 0xA0:
            self.C |= 1 - self.getbit(b1); n = 2
        elif op == 0xB0:
            self.C &= 1 - self.getbit(b1); n = 2
        elif op == 0x73:
            npc = (self.A + self.DPTR) & 0xFFFF
        elif op == 0x74:
            self.A = b1; n = 2
        elif op == 0x75:
            self.wr(b1, b2); n = 3
        elif op in (0x76, 0x77):
            self.iram[self.R(op - 0x76)] = b1; n = 2
        elif 0x78 <= op <= 0x7F:
            self.setR(op - 0x78, b1); n = 2
        elif op == 0x83:
            self.A = self.code((pc + 1 + self.A) & 0xFFFF)
        elif op == 0x84:
            if self.B == 0:
                self.C = 0; self._psw(None, True)
            else:
                q, r = divmod(self.A, self.B); self.A, self.B = q, r
                self.C = 0; self._psw(None, False)
        elif op == 0x85:
            self.wr(b2, self.rd(b1)); n = 3
        elif op in (0x86, 0x87):
            self.wr(b1, self.iram[self.R(op - 0x86)]); n = 2
        elif 0x88 <= op <= 0x8F:
            self.wr(b1, self.R(op - 0x88)); n = 2
        elif op == 0x90:
            self.DPTR = (b1 << 8) | b2; n = 3
        elif op == 0x92:
            self.setbit(b1, self.C); n = 2
        elif op == 0x93:
            self.A = self.code((self.A + self.DPTR) & 0xFFFF)
        elif op == 0x94:
            self._subb(b1); n = 2
        elif hi == 9 and lo >= 5:
            self._subb(src())
        elif op == 0xA2:
            self.C = self.getbit(b1); n = 2
        elif op == 0xA3:
            self.DPTR = (self.DPTR + 1) & 0xFFFF
        elif op == 0xA4:
            r = self.A * self.B; self.A, self.B = r & 0xFF, r >> 8
            self.C = 0; self._psw(None, r > 0xFF)
        elif op == 0xA5:
            raise RuntimeError('reserved opcode A5 at %04X' % pc)
        elif op in (0xA6, 0xA7):
            self.iram[self.R(op - 0xA6)] = self.rd(b1); n = 2
        elif 0xA8 <= op <= 0xAF:
            self.setR(op - 0xA8, self.rd(b1)); n = 2
        elif op == 0xB2:
            self.setbit(b1, 1 - self.getbit(b1)); n = 2
        elif op == 0xB3:
            self.C = 1 - self.C
        elif 0xB4 <= op <= 0xBF:                                # CJNE
            a, v = {0xB4: (self.A, b1), 0xB5: (self.A, self.rd(b1))}.get(op, (None, None))
            if op in (0xB6, 0xB7):
                a, v = self.iram[self.R(op - 0xB6)], b1
            elif op >= 0xB8:
                a, v = self.R(op - 0xB8), b1
            self.C = a < v; n = 3
            if a != v:
                npc = rel(b2, 3)
        elif op == 0xC0:
            self.push(self.rd(b1)); n = 2
        elif op == 0xC2:
            self.setbit(b1, 0); n = 2
        elif op == 0xC3:
            self.C = 0
        elif op == 0xC4:
            self.A = ((self.A << 4) | (self.A >> 4))
        elif op == 0xC5:
            v = self.rd(b1); self.wr(b1, self.A); self.A = v; n = 2
        elif hi == 0xC and lo >= 6:
            v = src(); dst(self.A); self.A = v
        elif op == 0xD0:
            self.wr(b1, self.pop()); n = 2
        elif op == 0xD2:
            self.setbit(b1, 1); n = 2
        elif op == 0xD3:
            self.C = 1
        elif op == 0xD4:                                        # DA A
            a = self.A
            if (a & 15) > 9 or (self.sfr[0xD0] & 0x40):
                a += 6
            if a > 0xFF:
                self.C = 1
            if ((a >> 4) & 15) > 9 or self.C:
                a += 0x60
            if a > 0xFF:
                self.C = 1
            self.A = a
        elif op == 0xD5:
            v = (self.rd(b1) - 1) & 0xFF; self.wr(b1, v); n = 3
            if v:
                npc = rel(b2, 3)
        elif op in (0xD6, 0xD7):
            r = self.R(op - 0xD6); m, a = self.iram[r], self.A
            self.A = (a & 0xF0) | (m & 15); self.iram[r] = (m & 0xF0) | (a & 15)
        elif 0xD8 <= op <= 0xDF:
            v = (self.R(op - 0xD8) - 1) & 0xFF; self.setR(op - 0xD8, v); n = 2
            if v:
                npc = rel(b1, 2)
        elif op == 0xE0:
            self.A = self.xread(self.DPTR)
        elif op in (0xE2, 0xE3):                                # MOVX A,@Ri: P2 is the high byte
            self.A = self.xread((self.sfr[0xA0] << 8) | self.R(op - 0xE2))
        elif op == 0xE4:
            self.A = 0
        elif hi == 0xE and lo >= 5:
            self.A = src()
        elif op == 0xF0:
            self.xwrite(self.DPTR, self.A)
        elif op in (0xF2, 0xF3):                                # MOVX @Ri,A: P2 is the high byte
            self.xwrite((self.sfr[0xA0] << 8) | self.R(op - 0xF2), self.A)
        elif op == 0xF4:
            self.A = ~self.A
        elif hi == 0xF and lo >= 5:
            dst(self.A)
        else:
            raise RuntimeError('internal error: opcode %02X at %04X not dispatched' % (op, pc))
        self.sfr[0xD0] = (self.sfr[0xD0] & ~1) | (bin(self.A).count('1') & 1)
        self.pc = npc if npc is not None else (pc + n) & 0xFFFF
        self.steps += 1

    def call(self, addr, maxn=200000, ret=0xFFF0):
        """Push the sentinel return address ret, run from addr until pc == ret (the routine's
        final RET) and return the number of instructions executed. Pick another ret if the
        image has code at 0xFFF0 that the routine may reach."""
        ra = ret
        self.push(ra & 0xFF); self.push(ra >> 8)
        self.pc, k = addr, 0
        while self.pc != ra:
            self.step(); k += 1
            if k >= maxn:
                raise RuntimeError('runaway at %04X' % self.pc)
        return k

    def run_until(self, addr, stops, maxn=200000):
        """Run from addr until pc is in stops and return that address. The check comes before
        each instruction: the stop instruction is not executed, and if addr itself is in
        stops nothing runs."""
        self.pc, k = addr, 0
        while self.pc not in stops:
            self.step(); k += 1
            if k >= maxn:
                raise RuntimeError('runaway at %04X' % self.pc)
        return self.pc


class Divider:
    """Partial model of the MediaTek arithmetic unit used for LBA <-> MSF: 0x403D-0x403F holds a
    24-bit operand (high byte first), writing 0x403B starts a command; 0x72 divides by 75 and
    0x62 by 60, leaving the quotient in 0x403D-0x403F and the remainder in 0x4043, and 0x403B
    reads back 0 (done). Inferred from the firmware's use, not from documentation. The firmware
    also uses commands 0x01-0x07, 0x13, 0x21; those raise an error here."""

    def attach(self, cpu):
        def hook(c, a, v):
            if a != 0x403B or not v:
                return False
            d = {0x62: 60, 0x72: 75}.get(v)
            if d is None:
                raise RuntimeError('divider command %02X not modelled' % v)
            x = (c.x.get(0x403D, 0) << 16) | (c.x.get(0x403E, 0) << 8) | c.x.get(0x403F, 0)
            q, r = divmod(x, d)
            c.x.update({0x403D: q >> 16 & 255, 0x403E: q >> 8 & 255, 0x403F: q & 255, 0x4043: r, 0x403B: 0})
            return True
        cpu.add_xw_hook(hook)
        return cpu
