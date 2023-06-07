import ctypes

# all this shit ported from kairos and liboffsetfinder64 

def BIT_RANGE(v, begin, end):
    v = ctypes.c_uint64(v).value   
    return ctypes.c_uint64((v >> begin) % (1 << (end - begin + 1))).value
def BIT_AT(v, pos):
    v = ctypes.c_uint64(v).value    
    return ctypes.c_uint64((v >> pos) % 2).value
def SET_BITS(v, begin):
    v = ctypes.c_uint64(v).value
    return ctypes.c_uint64(v << begin).value

# -- DECODERS --

def signExtend(x, M):
    extended = (x & 1 << (M-1))>>(M-1)
    for i in range(M, 64):
        x |= extended << i
    return x

def get_type(data): # from kairos
    if BIT_RANGE(data, 24, 28) == 0x10 and data >> 31:
        return 'adrp'
    elif BIT_RANGE(data, 24, 28) == 0x10 and (not (data >> 31)):
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

def supertype(type):
    if type in ('bl', 'cbz', 'cbnz', 'tbnz', 'bcond', 'b'):
        return 'sut_branch_imm'
    elif type in ('ldr', 'ldrh', 'ldrb', 'ldxr', 'str', 'strb', 'stp'):
        return 'sut_memory'
    else:
        return 'sut_general'
def subtype(opcode, type):
    if type == 'ldrh':
        if BIT_RANGE(opcode, 21, 31) == 67 and BIT_RANGE(opcode, 10, 11) == 2:
            return 'reg'
        else:
            return 'imm'
    elif type == 'ldr':
        if ((opcode >> 22) | (1 << 8)) == 0b1111100001 and BIT_RANGE(opcode, 10, 11) == 2:
            return 'reg'
        elif (opcode >> 31) or (BIT_RANGE(opcode | SET_BITS(1, 30), 22, 31) == 0b1111100101):
            return 'imm'
        else:
            return 'literal'
    elif type == 'ldrb':
        if BIT_RANGE(opcode, 21, 31) == 0b00111000011 and BIT_RANGE(opcode, 10, 11) == 2:
            return 'reg'
        else:
            return 'imm'
    elif type == 'strb':
        if BIT_RANGE(opcode, 21, 31) == 0b00111000001 and BIT_RANGE(opcode, 10, 11) == 2:
            return 'reg'
        else:
            return 'imm'
    elif type == 'subs':
        if BIT_RANGE(opcode, 21, 30) == 0b1101011001:
            return 'reg_extended'
        elif BIT_RANGE(opcode, 24, 30) == 107:
            return 'reg'
        elif BIT_RANGE(opcode, 24, 30) == 113:
            return 'imm'
        return None
    elif type == 'ccmp':
        if BIT_RANGE(opcode, 21, 30) == 0b1111010010:
            return 'reg'
        return None
    elif type in ('movz', 'movk'):
        return 'imm'
    elif type == 'mov':
        return 'reg'
    return 'general'

def imm(pc, opcode, type) -> int:
    st = subtype(opcode, type)
    if type == 'adr':
        return pc + signExtend((BIT_RANGE(opcode, 5, 23) << 2) | (BIT_RANGE(opcode, 29, 30)), 21)
    elif type == 'b':
        return pc + ((opcode % (1 << 26)) << 2)
    elif type == 'adrp':
        return ((pc >> 12) << 12) + signExtend(ctypes.c_uint64((((((opcode % (1 << 24)) >> 5) <<2) | BIT_RANGE(opcode, 29, 30)))).value << 12, 32)
    elif type in ('add', 'sub', 'subs'):
        return BIT_RANGE(opcode, 10, 21) << (((opcode >> 22) & 1) * 12)
    elif type == 'bl':
        return pc + (signExtend(opcode % (1 << 26), 25) << 2)
    elif type in ('cbz', 'cbnz', 'bcond'):
        return pc + (signExtend(BIT_RANGE(opcode, 5, 23), 19) << 2)
    elif type == 'tbnz':
        return pc + (signExtend(BIT_RANGE(opcode, 5, 18), 13) << 2)
    elif type in ('movk', 'movz'):
        return (ctypes.c_uint64(BIT_RANGE(opcode, 5, 20)).value) << (BIT_RANGE(opcode, 21, 22) * 16)
    elif type == 'ldr':
        if st == 'st_immediate':
            if BIT_RANGE(opcode | SET_BITS(1, 30), 22, 31) == 0b1111100101:
                return BIT_RANGE(opcode, 10, 21) << BIT_RANGE(opcode, 30, 31)
            if BIT_RANGE(opcode, 24, 25):
                return BIT_RANGE(opcode, 10, 21) << (opcode >> 30)
            else:
                return signExtend(BIT_RANGE(opcode, 12, 21), 9)
        elif st == 'st_literal':
            return BIT_RANGE(opcode, 5, 23) << 2
        else:
            return -1 #can't get imm value of ldr that has non immediate subtype
    elif type == 'strb':
        if st != 'st_immediate':
            return -1
        if BIT_RANGE(opcode, 22, 31) == 0b0011100100:
            return BIT_RANGE(opcode, 12, 20)
        else:
            return BIT_RANGE(opcode, 10, 21)
    elif type == 'ldrh':
        if st != 'st_immediate':
            return -1
        if ((BIT_RANGE(opcode, 21, 31) == 0b01111000010)
         and ((BIT_RANGE(opcode, 10, 11) == 0b01) or (BIT_RANGE(opcode, 10, 11) == 0b11))):
                return BIT_RANGE(opcode, 12, 20)
        else:
            return BIT_RANGE(opcode, 10, 21) << BIT_RANGE(opcode, 30, 31)
    elif type == 'ldrb':
        if st != 'st_immediate':
            return -1
        if BIT_RANGE(opcode, 22, 31) == 0b0011100101:
            return BIT_RANGE(opcode, 10, 21) << BIT_RANGE(opcode, 30, 31);
        else:
            return BIT_RANGE(opcode, 12, 20) << BIT_RANGE(opcode, 30, 31);
    elif type == 'str':
        return BIT_RANGE(opcode, 10, 21) << (opcode >> 30)
    # orr, and_ unsupported
    elif type == 'tbz':
        return BIT_RANGE(opcode, 5, 18)
    elif type == 'stp':
        return signExtend(BIT_RANGE(opcode, 15, 21), 7) << (2 + (opcode >> 31))
    return -1

def rd(opcode, type) -> int:
    if type in ('subs', 'adrp', 'adr', 'add', 'sub', 'movk', 'orr', 'and_', 'movz', 'mov', 'csel', 'pacib', 'pacizb'):
        return opcode % (1 << 5)
    return 0

def rn(opcode, type) -> int:
    if type in ('subs', 'add', 'sub', 'ret', 'br', 'orr', 'and_', 'ldxr', 'ldrb', 'str', 'strb', 'ldr', 'ldrh', 'stp', 'csel', 'mov', 'ccmp', 'pacib', 'pacizb'):
        return BIT_RANGE(opcode, 5, 9)
    return 0

def rm(opcode, type) -> int:
    if type == 'ccmp':
        if subtype(opcode, type) != 'reg':
            return 0
    elif type in ('csel', 'mov', 'subs'):
        return BIT_RANGE(opcode, 16, 20)
    elif type == 'br':
        return BIT_RANGE(opcode, 0, 4)
    return 0

# -- INSTRUCTIONS --

def new_insn_adr(pc, imm, rd):
    rd = ctypes.c_uint8(rd).value
    opcode = 0
    opcode |= SET_BITS(16, 24)
    opcode |= SET_BITS(rd & 31, 0)
    if imm > pc:
        if (imm - pc) >= (1 << 20):
            return -1
    else:
        if (pc - imm) >= (1 << 20):
            return -1
    imm -= pc
    opcode |= SET_BITS(BIT_RANGE(imm, 0, 1), 29)
    opcode |= SET_BITS(BIT_RANGE(imm, 2, 20), 5)
    return opcode

def new_register_mov(pc, imm, rd, rn, rm):
    opcode = 0
    opcode |= SET_BITS(42, 24) | SET_BITS(1, 31)
    opcode |= (rd % (1 << 5))
    opcode |= SET_BITS(rm & 31, 16)
    opcode |= SET_BITS(rn & 31, 5)
    opcode |= SET_BITS(imm & 63, 10)
    return ctypes.c_uint32(opcode).value

