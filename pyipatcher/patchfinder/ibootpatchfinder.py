# all patches are ported from kairos

from pyipatcher.patchfinder.patchfinder64 import patchfinder64#, insn
import insn
import struct
from pyipatcher.logger import get_my_logger

def make_zeroes(n):
    zeroes = b''
    for i in range(n):
        zeroes += b'\x00'
    return zeroes

class ibootpatchfinder(patchfinder64):
    def __init__(self, buf: bytes, verbose: bool):
        super().__init__(buf)
        self.verbose = verbose
        self.vers, self.minor_vers = self.get_iboot_ver()
        print(f'iBoot-{self.vers} inputted')
        self.base = self.get_base()
        print(f'Base address: {hex(self.base)}')

    @property
    def has_kernel_load(self):
        return self.memmem(b'__PAGEZERO') != -1
    
    @property
    def has_recovery_console(self):
        return self.memmem(b'Entering recovery mode, starting command prompt') != 1
    
    def get_iboot_ver(self):
        ver_arrs = self.get_str(b'iBoot-', 9, end=True).split(b'.')
        return int(ver_arrs[0]), int(ver_arrs[1])
    
    def get_base(self):
        offset = 0x300 if self.vers >= 6603 else 0x318
        return struct.unpack("<Q", self._buf[offset:offset+8])[0]

    def iboot_memmem(self, needle):
        needle = (needle + self.base).to_bytes(8, byteorder='little') 
        return self.memmem(needle)
        
    def get_debug_enabled_patch(self):
        logger = get_my_logger(self.verbose)
        debug_enabled_loc = self.memmem(b'debug-enabled')
        assert debug_enabled_loc != -1
        logger.debug(f'debug_enabled_loc={hex(debug_enabled_loc)}')
        debug_enabled_ref = self.xref(debug_enabled_loc)
        assert debug_enabled_ref != 0
        logger.debug(f'debug_enabled_ref={hex(debug_enabled_ref)}')
        self.apply_patch(debug_enabled_ref, b'\x20\x00\x80\xD2')
        return 0 
       
    def get_cmd_handler_patch(self, command, ptr):
        logger = get_my_logger(self.verbose)
        cmd = bytes('\0' + command + '\0', 'utf-8')
        cmd_loc = self.memmem(cmd)
        if cmd_loc == -1:
            logger.error(f'Could not find command \"{command}\"')
            return -1
        cmd_loc += 1
        logger.debug(f'cmd_loc={hex(cmd_loc)}')
        cmd_ref = self.iboot_memmem(cmd_loc)
        if cmd_ref == -1:
            logger.error('Could not find command ref')
            return -1
        logger.debug(f'cmd_ref={hex(cmd_ref)}')
        self.apply_patch(cmd_ref+8, ptr.to_bytes(8, byteorder='little'))
        return 0
        
    def get_unlock_nvram_patch(self):
        logger = get_my_logger(self.verbose)
        debuguart_loc = self.memmem(b'debug-uarts')
        if debuguart_loc == -1:
            logger.error('Could not find debug-uarts string')
            return -1
        logger.debug(f'debuguart_loc={hex(debuguart_loc + self.base)}')
        debuguart_ref = self.iboot_memmem(debuguart_loc)
        logger.debug(f'debuguart_ref={hex(debuguart_ref)}')
        setenv_whitelist = debuguart_ref
        try:
            while struct.unpack("<Q", self._buf[setenv_whitelist:setenv_whitelist+8])[0]:
                setenv_whitelist -= 8
        except:
            pass
        setenv_whitelist += 8
        logger.debug(f'setenv_whitelist={hex(setenv_whitelist)}')
        blacklistfunc = self.xref(setenv_whitelist)
        if blacklistfunc == 0:
            logger.error('Could not find setenv whitelist ref')
            return -1
        logger.debug(f'blacklistfunc={hex(blacklistfunc)}')
        blacklistfunc_begin = self.bof(blacklistfunc)
        if blacklistfunc_begin == 0:
            logger.error('Could not find beginning of blacklistfunc')
            return -1
        logger.debug(f'blacklistfunc_begin={hex(blacklistfunc_begin + self.base)}')
        self.apply_patch(blacklistfunc_begin, b'\x00\x00\x80\xd2\xc0\x03_\xd6')
        env_whitelist = setenv_whitelist
        try:
            while struct.unpack("<Q", self._buf[env_whitelist:env_whitelist+8])[0]:
                env_whitelist += 8
        except:
            pass
        env_whitelist += 8
        logger.debug(f'env_whitelist={hex(env_whitelist)}')
        blacklistfunc2 = self.xref(env_whitelist)
        if blacklistfunc2 == 0:
            logger.error('Could not find env whitelist ref')
            return -1
        logger.debug(f'blacklistfunc2={hex(blacklistfunc2)}')
        blacklistfunc2_begin = self.bof(blacklistfunc2)
        if blacklistfunc_begin == 0:
            logger.error('Could not find beginning of blacklistfunc2')
            return -1
        self.apply_patch(blacklistfunc2_begin, b'\x00\x00\x80\xd2\xc0\x03_\xd6')
        com_apple_system_loc = self.memmem(b'com.apple.System.\0')
        if com_apple_system_loc == -1:
            logger.error('Could not find com_apple_system_loc')
            return -1
        logger.debug(f'com_apple_system_loc={hex(com_apple_system_loc + self.base)}')
        com_apple_system_ref = self.xref(com_apple_system_loc)
        logger.debug(f'com_apple_system_ref={hex(com_apple_system_ref)}')
        com_apple_system_begin = self.bof(com_apple_system_ref)
        if com_apple_system_begin == 0:
            logger.error('Could not find com_apple_system_begin')
            return -1
        logger.debug(f'com_apple_system_begin={hex(com_apple_system_begin + self.base)}')
        self.apply_patch(com_apple_system_begin, b'\x00\x00\x80\xd2\xc0\x03_\xd6')
        return 0

    def get_bootarg_patch(self, bootargs):
        logger = get_my_logger(self.verbose)
        bootargs = bytes(bootargs, 'utf-8')
        default_loc = 0
        if (self.vers == 6723 and self.minor_vers >= 100) or self.vers >= 7429:
            default_loc = self.memmem(b'rd=md0')
        else:
            default_loc = self.memmem(b'rd=md0 nand-enable-reformat=1 -progress')
        if default_loc == -1:
            logger.debug('Could not find default bootargs string, searching for alternative boot-args')
            if (self.vers == 6723 and self.minor_vers >= 100) or self.vers >= 7429:
                default_loc = self.memmem(b'-progress')
            else:
                default_loc = self.memmem(b'rd=md0 -progress -restore')
        if default_loc == -1:
            logger.error('Could not find boot-arg string')
            return -1
        logger.debug(f'default_loc={hex(default_loc)}')
        default_ba_ref = self.xref(default_loc)
        if (self.vers == 6723 and self.minor_vers >= 100) or self.vers >= 7429:
            default_ba_ref = insn.get_next_nth_insn(self._buf, default_ba_ref, 5, 'nop')
        if default_ba_ref == 0:
            logger.error('Could not find boot-arg xref')
            return -1
        logger.debug(f'default_ba_ref={hex(default_ba_ref)}')
        if len(bootargs) > 270:
            logger.debug('Oversized bootargs, truncating...')
            bootargs = bootargs[:270]
            logger.warn(f'Truncated bootargs: {bootargs.decode()}')
        zeroes = make_zeroes(270)
        new_loc = 0
        new_loc = self.memmem(zeroes)
        if new_loc == -1:
            logger.warn('Could not find 270 zeroes')
            if len(bootargs) >= 180:
                logger.debug(f'Truncating bootargs again')
                bootargs = bootargs[:179]
                logger.debug(f'Truncated bootargs: {bootargs.decode()}')
            new_loc = self.memmem(b'Reliance on this')
            if new_loc == -1:
                logger.error('Could not find long string to override')
                return -1
            zeroes = make_zeroes(179)
        else:
            new_loc += 16
            zeroes = make_zeroes(270)
        _insn = self.get_insn(default_ba_ref)
        type = insn.get_type(_insn)
        if type == 'unknown':
            return -1
        if type in ('adr', 'nop'):
            new_adr = 0
            if (self.vers == 6723 and self.minor_vers >= 100) or self.vers >= 7429:
                reg = 24
                default_loc = self.memmem(b'-restore')
                if default_loc == -1:
                    logger.warn('Could not find restore bootarg string, defaulting to the x24 register')
                else:
                    restore_string_ref = self.xref(default_loc)
                    while insn.get_type(self.get_insn(restore_string_ref)) != 'sub':
                        restore_string_ref -= 4
                    sub_insn = self.get_insn(restore_string_ref)
                    reg = ctypes.c_int((sub_insn & 0xFF) - 160).value
                new_adr = insn.new_insn_adr(default_ba_ref, address)



    def get_sigcheck_patch(self):
        pass