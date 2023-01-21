import struct
import ctypes
import sys

def BIT_RANGE(v, begin, end):   return (v >> begin) % (1 << (end - begin + 1))
def BIT_AT(v, pos): return (v >> pos) % 2
def SET_BITS(v, begin): return v << begin


def arm64_branch_instruction(_from, to):
    _from = ctypes.c_ulonglong(_from).value
    to = ctypes.c_ulonglong(to).value
    return 0x18000000 - (_from - to) / 4 if _from > to else 0x14000000 + (to - _from) / 4

def get_type(data): # from kairos
    if BIT_RANGE(data, 24, 28) == 0x10 and data >> 31:
        return 'adrp'
    elif BIT_RANGE(data, 24, 28) == 0x10 and (not data >> 31):
        return 'adr'
    elif BIT_RANGE(data, 24, 30) == 0x11:
        return 'add'
    elif BIT_RANGE(data, 24, 30) == 0x51:
        return 'sub'
    elif data >> 26 == 0x25:
        return 'bl'
    elif BIT_RANGE(data, 24, 30) == 0x34:
        return 'cbz'
    elif ((0x1F << 5) | data) == 0xD65F03E0:
        return 'ret'
    elif BIT_RANGE(data, 24, 30) == 0x37:
        return 'tbnz'
    elif ((0x1F << 5) | data) == 0xD61F03E0:
        return 'br'
    elif (((data >> 22) | 0x100) == 0x3E1 and ((data >> 10) % 4)) or ((data>>22 | 0x100) == 0x3E5) or ((data >> 23) == 0x18):
        return 'ldr'
    elif BIT_RANGE(data, 24, 30) == 0x35:
        return 'cbnz'
    elif BIT_RANGE(data, 23, 30) == 0xE5:
        return 'movk'
    elif BIT_RANGE(data, 23, 30) == 0x64:
        return 'orr'
    elif BIT_RANGE(data, 23, 30) == 0x24:
        return 'and_'
    elif BIT_RANGE(data, 24, 30) == 0x36:
        return 'tbz'
    elif (BIT_RANGE(data, 24, 29) == 0x8) and (data >> 31) and BIT_AT(data, 22):
        return 'ldxr'
    elif BIT_RANGE(data, 21, 31) == 0x1C2 or BIT_RANGE(data, 22, 31) == 0xE5 or ((BIT_RANGE(data, 21, 31) == 0x1C3 and BIT_RANGE(data, 10, 11) == 0x2)):
        return 'ldrb'
    elif (BIT_RANGE(data, 22, 29) == 0xE4) and (data >> 31):
        return 'str'
    elif (BIT_RANGE(data, 25, 30) == 0x14) and (not BIT_AT(data, 22)):
        return 'stp'
    elif (BIT_RANGE(data, 23, 30) == 0xA5):
        return 'movz'
    elif (BIT_RANGE(data, 24, 30) == 0x2A) and (BIT_AT(data, 21) == 0x0):
        return 'mov'
    elif (BIT_RANGE(data, 24, 31) == 0x54) and not BIT_AT(data, 4):
        return 'bcond'
    elif (BIT_RANGE(data, 26, 31) == 0x5):
        return 'b'
    elif (BIT_RANGE(data, 12, 31) == 0xD5032) & (0x1F % (1<<5)):
        return 'nop'
    elif (BIT_RANGE(data, 21, 30) == 0xD4) and (BIT_RANGE(data, 10, 11) == 0x0):
        return 'csel'
    elif BIT_RANGE(data, 20, 31) == 0xD53:
        return 'mrs'
    elif (BIT_RANGE(data, 21, 30) == 0x359) or (BIT_RANGE(data, 24, 30) == 0x6B) or (BIT_RANGE(data, 24, 30) == 0x71):
        return 'subs'
    elif BIT_RANGE(data, 21, 30) == 0x3D2:
        return 'ccmp'
    else:
        return 'unknown'
 


class patchfinder64:
    def __init__(self, buf):
        self._buf = bytearray(buf)
        self.size = len(buf)
        if self.size % 4 != 0:
            raise Exception('arm64 file size not divisible by 4')

    def memmem(self, needle, end=False):
        if end:
            return self._buf.find(needle)+len(needle)
        else:
            return self._buf.find(needle)

    def get_str(self, start, size, end=False):
        where = self.memmem(start, end)
        return self._buf[where:where+size]

    def get_insn(self, where):
        if self.size - where < 4:
            raise Exception('offset reached end of file')
        return struct.unpack("<I", self._buf[where:where+4])[0]
        
    def step(self, start, length, what, mask):
        end = start + length
        while start < end:
            x = struct.unpack("<I", self._buf[start:start+4])[0]
            if (x & mask) == what:
                return start
            start += 4
        return 0
     
    def step_back(self, start, length, what, mask):
        end = start - length
        while start >= end:
            x = struct.unpack("<I", self._buf[start:start+4])[0]
            if (x & mask) == what:
                return start
            start -= 4
        return 0

    def bof(self, start, where):
        while where >= start:
            op = struct.unpack("<I", self._buf[where:where+4])[0]
            if (op & 0xFFC003FF) == 0x910003FD:
                delta = (op >> 10) & 0xFFF
                if (delta & 0xF) == 0:
                    prev = where - ((delta >> 4) + 1) * 4
                    au = struct.unpack("<I", self._buf[prev:prev+4])[0]
                    if (au & 0xFFC003E0) == 0xA98003E0:
                        return prev
                    # try something else
                    while where > start:
                        where -= 4
                        au = struct.unpack("<I", self._buf[where:where+4])[0]
                        if (au & 0xFFC003FF) == 0xD10003FF and ((au >> 10) & 0xFFF) == delta + 0x10:
                            return where
                        if (au & 0xFFC003E0) != 0xA90003E0:
                            where += 4
                            break
            where -= 4
        return 0

    def follow_call(self, call):
        w = ctypes.c_longlong(struct.unpack("<I", self._buf[call:call+4])[0] & 0x3FFFFFF).value
        w = ctypes.c_longlong(w << (64 - 26)).value
        w = ctypes.c_longlong(w >> (64-26-2)).value
        return call + w

    def xref(self, what):
        value = [0] * 32
        end = self.size & ~3
        for i in range(0, end, 4): 

            op = struct.unpack("<I", self._buf[i:i+4])[0]
            reg = op & 0x1F
            if (op & 0x9F000000) == 0x90000000:
                adr = ctypes.c_int(((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8)).value
                value[reg] = ctypes.c_ulonglong((adr << 1) + (i & ~0xFFF)).value
                continue
            elif (op & 0xFF000000) == 0x91000000:
                rn = (op >> 5) & 0x1F
                shift = (op >> 22) & 3
                imm = (op >> 10) & 0xFFF
                if shift == 1:
                    imm <<= 12
                else:
                    if shift > 1:   continue
                value[reg] = value[rn] + imm
            elif (op & 0xF9C00000) == 0xF9400000:
                rn = (op >> 5) & 0x1F
                imm = ((op >> 10) & 0xFFF) << 3
                if imm == 0:
                    continue
                value[reg] = value[rn] + imm
            elif (op & 0x9F000000) == 0x10000000:
                adr = ctypes.c_int(((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8)).value
                value[reg] = ctypes.c_ulonglong((adr >> 11) + i).value
            elif (op & 0xFF000000) == 0x58000000:
                value[reg] = adr + i
            if value[reg] == what:
                return i
        return 0

    def apply_patch(self, where, patch):
        self._buf[where:where+len(patch)] = patch


def test():
    set_package_name("test")
    kernel = open("kcache.raw", "rb").read()
    pf = patchfinder64(kernel)
    ret = pf.step(16223228, 100, 0x94000000, 0xFC000000)

    print(f"returned: {pf.step(ret, 100, 0x94000000, 0xFC000000)}")


