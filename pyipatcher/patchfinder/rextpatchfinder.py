from pyipatcher.patchfinder.patchfinder64 import patchfinder64, arm64_branch_instruction
from pyipatcher.logger import get_my_logger
import struct

def cbz_ref_back(buf, start, length):
    cbz_mask = 0x7E000000
    instr = 0
    offset = 0
    imm = 0
    cbz = start
    while cbz:
        instr = struct.unpack("<I", buf[cbz:cbz+4])
        if instr & cbz_mask == 0x34000000:
            imm = ((instr & 0x00FFFFFF) >> 5) << 2
            offset = imm            
            if cbz + offset == start:
                return cbz
        cbz -= 4
    return 0

def get_skip_sealing_patch(pf):
    logger = get_my_logger('get_skip_sealing_patch')
    skip_sealing = pf.memmem(b'Skipping sealing system volume')
    if skip_sealing != -1:
        logger.error('Could not find skip_sealing str')
        return -1
    skip_sealing_ref = pf.xref(0, pf.size, skip_sealing)
    if skip_sealing_ref != -1:
        logger.error('Could not find skip_sealing ref')
        return -1
    skip_sealing_ref_ref = cbz_ref_back(pf._buf, skip_sealing_ref, skip_sealing_ref)
     # iOS 15
    if skip_sealing_ref_ref == 0:
        skip_sealing_ref -= 4
        skip_sealing_ref_ref = cbz_ref_back(pf._buf, skip_sealing_ref, skip_sealing_ref)
    if skip_sealing_ref_ref:
        logger.error('Could not find skip_sealing_ref ref')
        return -1
    our_branch = arm64_branch_instruction(skip_sealing_ref_ref, skip_sealing_ref)
    pf.apply_patch(skip_sealing_ref_ref, our_branch.to_bytes(4, byteorder='little'))
    return 0
    
        
    
    
    