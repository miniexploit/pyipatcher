from .patchfinder64 import patchfinder64, retassure, assure
import struct
from pyipatcher.logger import get_my_logger

class ibootpatchfinder:
    def __init__(self, pf):
        self.pf = pf
        self.vers = self.get_iboot_major_ver()
        print(f'iBoot-{self.vers} inputted')
        self.base = self.get_base()
        print(f'Base address: {hex(self.base)}')
    
    def get_iboot_major_ver(self):
        return int(self.pf.get_str(b'iBoot-', 4, end=True))
    
    def get_base(self):
        offset = 0x300 if self.iboot_vers >= 6603 else 0x318
        return struct.unpack("<Q", self.pf._buf[offset:offset+8])[0]
    
    def get_iboot_adr(x):   return x + self.base
    def iboot_ref(self, pat):   self.pf.xref(0, self.pf.size, pat)
        
    def get_debug_enabled_patch(self):
        logger = get_my_logger('get_debug_enabled_patch')
        debug_loc = self.pf.memmem("debug-enabled")
        assure(debug_loc != -1)
        logger.debug(f'Found \"debug-enabled\" str loc at {hex(debug_loc)}')
        debug_enabled_ref = self.pf.xref(0, self.pf.size, debug_loc)
        assure(debug_enabled_ref != 0)
        print(f'Found \"debug-enabled\" str ref at {hex(debug_enabled_ref)}')
        pf.apply_patch(debug_enabled_ref, b'\x20\x00\x80\xD2') 
       
    def get_sigcheck_patch(self):
        logger = get_my_logger('get_sigcheck_patch')
        img4decodemanifestexists = 0
        if self.vers >= 5540:
            logger.debug(f'iOS 13.4 or later iBoot detected')
            img4decodemanifestexists = self.pf.memmem(b'\xE8\x03\x00\xAA\xC0\x00\x80\x52\xE8\x00\x00\xB4')
        elif 3406 <= self.vers < 5540:
            logger.debug('iOS 13.3 or lower iBoot detected')
            img4decodemanifestexists = pf.memmem(b'\xE8\x03\x00\xAA\xE0\x07\x1F\x32\xE8\x00\x00\xB4')
        else:
            logger.error('iOS version not supported yet')
            return
        logger.debug(f'Found img4decodemanifestexists at {hex(img4decodemanifestexists)}')
        
       
            
            
        
        
        
        
    