from pyipatcher.patchfinder.patchfinder64 import patchfinder64
import struct
from pyipatcher.logger import get_my_logger

verbose = 0

class ibootpatchfinder(patchfinder64):
    def __init__(self, buf):
        raise NotImplementedError()
        super().__init__(buf)
        self.vers = self.get_iboot_major_ver()
        print(f'iBoot-{self.vers} inputted')
        self.base = self.get_base()
        print(f'Base address: {hex(self.base)}')

    @property
    def has_kernel_load(self):
        return self.memmem(b'__PAGEZERO') != -1
    
    @property
    def has_recovery_console(self):
        return self.memmem(b'Entering recovery mode, starting command prompt') != 1
    
    def get_iboot_major_ver(self):
        return int(self.get_str(b'iBoot-', 4, end=True))
    
    def get_base(self):
        offset = 0x300 if self.vers >= 6603 else 0x318
        return struct.unpack("<Q", self._buf[offset:offset+8])[0]
        
    def get_debug_enabled_patch(self):
        logger = get_my_logger(verbose)
        debug_loc = self.memmem(b'debug-enabled')
        assert debug_loc != -1
        logger.debug(f'Found \"debug-enabled\" str loc at {hex(debug_loc)}')
        debug_enabled_ref = self.xref(debug_loc)
        assert debug_enabled_ref != 0
        logger.debug(f'Found \"debug-enabled\" str ref at {hex(debug_enabled_ref)}')
        self.apply_patch(debug_enabled_ref, b'\x20\x00\x80\xD2') 
       
    def get_cmd_hanlder_patch(self, command, ptr):
        logger = get_my_logger(verbose)
        cmd = bytes('\0' + command, 'utf-8')
        cmd_loc = self.memmem(cmd)
        if cmd_loc == -1:
            logger.error(f'Could not find command \"{command}\"')
            return -1
        cmd_ref = cmd_loc + self.base
        logger.debug(f'Found \"{command}\" at {hex(cmd_loc)} looking for {hex(cmd_ref)}')
        self.apply_patch(cmd_ref+8, ptr.to_bytes(8, byteorder='little'))
        
    def get_unlock_nvram_patch(self):
        logger = get_my_logger(verbose)
        debuguart_loc = self.memmem(b'debug-uarts')
        if debuguart_loc == -1:
            logger.error('Could not find debug-uarts string')
            return -1
        logger.debug(f'debuguart_loc={hex(debuguart_loc)}')
        debuguart_ref = debuguart_loc + self.base
        logger.debug(f'debuguart_ref={hex(debuguart_ref)}')
        setenv_whitelist = debuguart_ref
        while struct.unpack("<Q", self._buf[setenv_whitelist:setenv_whitelist+8])[0]:
            setenv_whitelist -= 8
        setenv_whitelist += 8
        logger.debug(f'setenv_whitelist={hex(setenv_whitelist)}')
        blacklistfunc = self.xref(setenv_whitelist)
        if blacklistfunc == 0:
            logger.error('Could not find setenv whitelist ref')
            return -1
        logger.debug(f'blacklistfunc={hex(blacklistfunc)}')
        blacklistfunc_begin = self.bof(0, blacklistfunc)
        if blacklistfunc_begin == 0:
            logger.error('Could not find blacklistfunc beginning')
            return -1
        logger.debug(f'blacklistfunc_begin={hex(blacklistfunc_begin)}')

    def get_sigcheck_patch(self):
        pass
            
            
        
        
        
        
    