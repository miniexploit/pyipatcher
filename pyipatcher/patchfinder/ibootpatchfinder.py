from .patchfinder64 import patchfinder64, retassure, assure
import struct

class ibootpatchfinder:
    def __init__(self, pf):
        self.pf = pf
        self.iboot_vers = self.get_iboot_major_ver()
        print(f'iBoot-{self.iboot_vers} inputted')
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
        debug_loc = self.pf.memmem("debug-enabled")
        assure(debug_loc != -1)
        print(f'get_debug_enabled_patch: Found \"debug-enabled\" str loc at {hex(debug_loc)}')
        debug_enabled_ref = self.pf.xref(0, self.pf.size, debug_loc)
        assure(debug_enabled_ref != 0)
        print(f'get_debug_enabled_patch: Found \"debug-enabled\" str ref at {hex(debug_enabled_ref)}')
        pf.apply_patch(debug_enabled_ref, b'\x20\x00\x80\xD2') 
        
        
        
    