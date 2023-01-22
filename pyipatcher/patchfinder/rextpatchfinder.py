from pyipatcher.patchfinder.patchfinder64 import patchfinder64, arm64_branch_instruction
from pyipatcher.logger import get_my_logger
import struct

class rextpatchfinder(patchfinder64):
    def __init__(self, buf: bytes, verbose: bool):
        super().__init__(buf)
        self.verbose = verbose

    def cbz_ref_back(self, start, length):
        cbz_mask = 0x7E000000
        instr = 0
        offset = 0
        imm = 0
        cbz = start
        while cbz:
            instr = struct.unpack("<I", self._buf[cbz:cbz+4])[0]
            if instr & cbz_mask == 0x34000000:
                imm = ((instr & 0x00FFFFFF) >> 5) << 2
                offset = imm            
                if cbz + offset == start:
                    return cbz
            cbz -= 4
        return 0

    def get_skip_sealing_patch(self):
        logger = get_my_logger(self.verbose)
        skip_sealing = self.memmem(b'Skipping sealing system volume')
        if skip_sealing == -1:
            logger.error('Could not find skip_sealing str')
            return -1
        logger.debug(f'skip_sealing={hex(skip_sealing)}')
        skip_sealing_ref = self.xref(skip_sealing)
        if skip_sealing_ref == 0:
            logger.error('Could not find skip_sealing ref')
            return -1
        logger.debug(f'skip_sealing_ref={hex(skip_sealing_ref)}')
        skip_sealing_ref_ref = self.cbz_ref_back(skip_sealing_ref, skip_sealing_ref)
         # iOS 15
        if skip_sealing_ref_ref == 0:
            skip_sealing_ref -= 4
            skip_sealing_ref_ref = self.cbz_ref_back(kip_sealing_ref, skip_sealing_ref)
        if skip_sealing_ref_ref == 0:
            logger.error('Could not find skip_sealing_ref ref')
            return -1
        logger.debug(f'skip_sealing_ref_ref={hex(skip_sealing_ref_ref)}')
        our_branch = arm64_branch_instruction(skip_sealing_ref_ref, skip_sealing_ref)
        self.apply_patch(skip_sealing_ref_ref, our_branch.to_bytes(4, byteorder='little'))
        return 0
    
        
    
    
    