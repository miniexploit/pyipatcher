import ctypes
import struct

def BIT_RANGE(v, begin, end):   return (v >> begin) % (1 << (end - begin + 1))
def BIT_AT(v, pos): return (v >> pos) % 2
def SET_BITS(v, begin): return v << begin

# -- DECODERS --

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

def get_next_nth_insn(buf, offset, n, type):
    for i in range(n):
        offset += 4
        while get_type(struct.unpack("<I", buf[offset:offset+4])[0]) != type:
            offset += 4
    return offset

def get_prev_nth_insn(buf, offset, n, type):
    for i in range(n):
        offset -= 4
        while get_type(struct.unpack("<I", buf[offset:offset+4])[0]) != type:
            offset -= 4
    return offset


# -- INSTRUCTIONS --

def new_insn_adr(offset, rd, addr):
    opcode = 0
    opcode |= SET_BITS(16, 24)
    opcode |= rd % (1 << 5)
    diff = addr - offset
    if diff > 0:
        if diff > (1 << 20):
            return -q
        elif -diff > (1 << 20):
            return -1
    opcode |= SET_BITS(BIT_RANGE(diff, 0, 1), 29)
    opcode |= SET_BITS(BIT_RANGE(diff, 2, 20), 5)
    return opcode
