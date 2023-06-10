# Ported from kairos and liboffsetfinder
# https://github.com/dayt0n/kairos
# https://github.com/Cryptiiiic/liboffsetfinder64

#from pyipatcher.patchfinder.patchfinder64 import patchfinder64
#from pyipatcher.patchfinder import insn
from pyipatcher.patchfinder.patchfinder64 import patchfinder64
from pyipatcher.patchfinder import insn
import struct, ctypes
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
        logger = get_my_logger(self.verbose, name='ibootpatchfinder')
        self.vers, self.minor_vers = self.get_iboot_ver()
        logger.debug(f'iBoot-{self.vers} inputted')
        if self.vers < 3406:
            raise NotImplementedError(f'Unsupported iBoot (iBoot-{self.vers}.{self.minor_vers}), only iOS 10 or later iBoot is supported')
        self.stage1 = (self._buf[0x200:0x200+5] == 'iBSS')
        self.stage2 =(self._buf[0x200:0x200+5] == 'iBEC')
        self.cpid = self.get_cpid()
        logger.debug(f'iBoot ChipID: {self.cpid}')
        self.base = self.get_base()
        logger.debug(f'Base address: {hex(self.base)}')

    @property
    def has_kernel_load(self):
        return self.memmem(b'__PAGEZERO') != -1
    
    @property
    def has_recovery_console(self):
        return self.memmem(b'Entering recovery mode, starting command prompt') != 1
    
    def get_iboot_ver(self):
        ver_arrs = self.get_str(b'iBoot-', 9, end=True).split(b'.')
        return int(ver_arrs[0]), int(ver_arrs[1])
    
    def get_cpid(self):
        cpid = self.get_str(b'platform-name\x00', 5, end=True)
        return int(cpid[1:])

    def get_base(self):
        offset = 0x300 if self.vers >= 6603 else 0x318
        return struct.unpack("<Q", self._buf[offset:offset+8])[0]

    def iboot_memmem(self, needle):
        needle = (needle + self.base).to_bytes(8, byteorder='little') 
        return self.memmem(needle)
        
    def get_debug_enabled_patch(self):
        logger = get_my_logger(self.verbose)
        debug_enabled_loc = self.memmem(b'debug-enabled')
        if debug_enabled_loc == -1:
            logger.error('Could not find "debug-enabled"')
        logger.debug(f'debug_enabled_loc={hex(debug_enabled_loc + self.base)}')
        debug_enabled_ref = self.xref(debug_enabled_loc)
        if debug_enabled_ref == 0:
            logger.error('Could not find debug_enabled_ref')
            return -1
        logger.debug(f'debug_enabled_ref={hex(debug_enabled_ref + self.base)}')
        bloff = self.step(debug_enabled_ref, self.size - debug_enabled_ref, 0x94000000, 0xFF000000)
        bloff2 = self.step(bloff, self.size - bloff, 0x94000000, 0xFF000000)
        self.apply_patch(bloff2, b'\x20\x00\x80\xD2')
        return 0 
       
    def get_cmd_handler_patch(self, command, ptr):
        logger = get_my_logger(self.verbose)
        cmd = bytes('\0' + command + '\0', 'utf-8')
        cmd_loc = self.memmem(cmd)
        if cmd_loc == -1:
            logger.error(f'Could not find command \"{command}\"')
            return -1
        cmd_loc += 1
        logger.debug(f'cmd_loc={hex(cmd_loc + self.base)}')
        cmd_ref = self.iboot_memmem(cmd_loc)
        if cmd_ref == -1:
            logger.error('Could not find command ref')
            return -1
        logger.debug(f'cmd_ref={hex(cmd_ref + self.base)}')
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
        logger.debug(f'debuguart_ref={hex(debuguart_ref + self.base)}')
        setenv_whitelist = debuguart_ref
        try:
            while self.get_ptr_loc(setenv_whitelist):
                setenv_whitelist -= 8
        except:
            pass
        setenv_whitelist += 8
        logger.debug(f'setenv_whitelist={hex(setenv_whitelist + self.base)}')
        blacklistfunc = self.xref(setenv_whitelist)
        if blacklistfunc == 0:
            logger.error('Could not find setenv whitelist ref')
            return -1
        logger.debug(f'blacklistfunc={hex(blacklistfunc + self.base)}')
        blacklistfunc_begin = self.bof(blacklistfunc)
        if blacklistfunc_begin == 0:
            logger.error('Could not find beginning of blacklistfunc')
            return -1
        logger.debug(f'blacklistfunc_begin={hex(blacklistfunc_begin + self.base)}')
        self.apply_patch(blacklistfunc_begin, b'\x00\x00\x80\xd2\xc0\x03_\xd6')
        env_whitelist = setenv_whitelist
        try:
            while self.get_ptr_loc(env_whitelist):
                env_whitelist += 8
        except:
            pass
        env_whitelist += 8
        logger.debug(f'env_whitelist={hex(env_whitelist + self.base)}')
        blacklistfunc2 = self.xref(env_whitelist)
        if blacklistfunc2 == 0:
            logger.error('Could not find env whitelist ref')
            return -1
        logger.debug(f'blacklistfunc2={hex(blacklistfunc2 + self.base)}')
        blacklistfunc2_begin = self.bof(blacklistfunc2)
        if blacklistfunc_begin == 0:
            logger.error('Could not find beginning of blacklistfunc2')
            return -1
        logger.debug(f'blacklistfunc2_begin={hex(blacklistfunc_begin + self.base)}')
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
        _bootargs = bytes(bootargs, 'utf-8')
        logger = get_my_logger(self.verbose)
        default_ba_str_loc = self.memmem(b'rd=md0 nand-enable-reformat=1 -progress')
        if default_ba_str_loc == -1:
            logger.debug('Could not find default bootargs string loc, searching for alternative bootargs string')
            default_ba_str_loc = self.memmem(b'rd=md0 -progress -restore')
            if default_ba_str_loc == -1:
                logger.debug('Alternative bootargs string 1 could not be found, searching for another alternative bootargs string')
                default_ba_str_loc = self.memmem(b'rd=md0')
                if default_ba_str_loc == -1:
                    logger.error('Could not find bootargs string')
                    return -1
        logger.debug(f'default_ba_str_loc={hex(default_ba_str_loc + self.base)}')
        _7429_0 = (self.vers >= 7429 and self.minor_vers >= 0)
        _6723_100 = ((self.vers == 6723 and self.minor_vers >= 100) or (self.vers > 6723)) and (not _7429_0)
        if _6723_100 or _7429_0:
            adr1 = self.xref(default_ba_str_loc)
            if adr1 == 0:
                logger.error('Could not find adr1')
                return -1
            logger.debug(f'adr1={hex(adr1 + self.base)}')
            boff = self.step(adr1, self.size - adr1, 0x14000000, 0xFC000000)
            bastackvarbranch = insn.imm(boff, self.get_insn(boff), 'b')
            if bastackvarbranch == -1:
                logger.error('Could not find bastackvarbranch')
                return -1
            logger.debug(f'bastackvarbranch={hex(bastackvarbranch)}')
            bloff = self.step(bastackvarbranch, self.size - bastackvarbranch, 0x94000000, 0xFF000000)
            nopoff = self.step_back(bloff, bloff, 0xd503201f, 0xFFFFFFFF)
            default_ba_xref = bastackvar = nopoff
            if default_ba_xref == 0:
                logger.error('Could not find default_ba_xref')
                return -1
            logger.debug(f'bastackvar={hex(bastackvar + self.base)}')
        else:
            default_ba_xref = self.xref(default_ba_str_loc)
            if default_ba_xref == 0:
                logger.error('Could not find default_ba_xref')
                return -1
            logger.debug(f'default_ba_xref={hex(default_ba_xref + self.base)}')
        logger.debug('Relocating boot-args string')
        _270zeroes = make_zeroes(270)
        ba_loc1 = self.memmem(_270zeroes, default_ba_xref)
        if self.cpid == 8010 or (self.cpid in (8000, 8003) and (not _7429_0)):
            logger.debug('Finding another bootarg location')
            ba_loc1 = self.memmem(_270zeroes, ba_loc1 + 270)
        logger.debug(f'ba_loc1={hex(ba_loc1 + self.base)}')
        if ba_loc1 != -1:
            ba_loc = ba_loc1 + 0x11
            logger.debug(f'ba_loc={hex(ba_loc + self.base)}')
            while True:
                if self.get_insn(ba_loc) == 0:
                    ba_loc += 4
                    if self.get_insn(ba_loc) == 0:
                        ba_loc -= 4
                        break
                    else:
                        ba_loc -= 4
                ba_loc += 4
            logger.debug(f'Pointing default bootargs xref to {hex(ba_loc + self.base -1 )}')
            default_ba_str_loc = ba_loc - 1
        else:
            cert_str_loc = self.memmem(b'Apple Inc.1')
            if cert_str_loc == -1:
                logger.error('Could not find "Apple Inc.1" string')
                return -1
            logger.debug(f'cert_str_loc={hex(cert_str_loc + self.base)}')
            logger.debug(f'Poiting default bootargs xref to {hex(cert_str_loc + self.base)}')
            default_ba_str_loc = cert_str_loc
        if _6723_100 or _7429_0:
            if insn.get_type(self.get_insn(default_ba_xref)) != 'nop':
                logger.error('Invalid instruction at default bootarg xref!')
                return -1
            adr2 = self.memmem(b' -restore')
            if adr2 == -1:
                logger.error('Could not find " -restore" string')
                return -1
            adr2_xref = self.xref(adr2)
            if adr2_xref == 0:
                logger.error('Could not find " -restore" string xref')
                return -1
            suboff = self.step_back(adr2_xref, adr2_xref, 0xd1000000, 0xff000000)
            _reg = insn.rd(self.get_insn(suboff), 'sub')
        else:
            if insn.get_type(self.get_insn(default_ba_xref)) != 'adr':
                default_ba_xref -= 8
                if insn.get_type(self.get_insn(default_ba_xref)) != 'bl':
                    logger.error('Invalid instruction at default bootarg xref!')
                    return -1
                default_ba_xref += 4
                _reg = insn.rd(self.get_insn(default_ba_xref), insn.get_type(self.get_insn(default_ba_xref)))
            else:
                if insn.get_type(self.get_insn(default_ba_xref)) != 'adr':
                    logger.error('Invalid instruction at default bootarg xref!')
                    return -1
                _reg = insn.rd(self.get_insn(default_ba_xref), 'adr')
        opcode = insn.new_insn_adr(default_ba_xref, default_ba_str_loc, _reg)
        self.apply_patch(default_ba_xref, opcode.to_bytes(4, byteorder='little'))
        logger.debug(f'Applying custom boot-args "{bootargs}"')
        self.apply_patch(default_ba_str_loc, _bootargs)
        if _6723_100 or _7429_0:
            xrefRD = 4
        else:
            xrefRD = insn.rd(self.get_insn(default_ba_xref), insn.get_type(self.get_insn(default_ba_xref)))
            if xrefRD == 0:
                logger.error('Could not find xrefRD')
                return -1
        logger.debug(f'xrefRD={xrefRD}')
        if xrefRD == 4 or xrefRD > 9:
            return 0
        cseloff = self.step(default_ba_xref, self.size - default_ba_xref, 0x1a800000, 0x7fe00c00)
        logger.debug(f'cseloff={hex(cseloff + self.base)}')
        if not (xrefRD in (insn.rn(self.get_insn(cseloff), 'csel'), insn.rm(self.get_insn(cseloff), 'csel'))):
            logger.error('Invalid default_ba_xref rd')
            return -1
        cselRD = insn.rd(self.get_insn(cseloff), 'csel')
        logger.debug(f'cselRD={cselRD}')
        opcode2 = insn.new_register_mov(cseloff, 0, cselRD, -1, xrefRD)
        logger.debug(f'({hex(cseloff + self.base)})patching: "mov x{cselRD}, x{xrefRD}"')
        self.apply_patch(cseloff, opcode2.to_bytes(4, byteorder='little'))
        cseloff -= 4
        while (insn.supertype(insn.get_type(self.get_insn(cseloff))) != 'sut_branch_imm') or (insn.get_type(self.get_insn(cseloff)) == 'bl'):
            cseloff -= 4
        logger.debug(f'branch_loc={hex(cseloff + self.base)}')
        cseloff = insn.imm(cseloff, self.get_insn(cseloff), insn.get_type(self.get_insn(cseloff)))
        if cseloff == -1:
            logger.error('Could not find branch_dst')
            return -1
        logger.debug(f'branch_dst={hex(cseloff + self.base)}')
        if insn.get_type(self.get_insn(cseloff)) != 'adr':
            adroff = self.step(cseloff, self.size - cseloff, 0x10000000, 0x9F000000)
        else:
            adroff = cseloff
        opcode3 = insn.new_insn_adr(adroff, default_ba_str_loc, adrrd := insn.rd(self.get_insn(adroff), insn.get_type(self.get_insn(adroff))))
        logger.debug(f'({hex(adroff + self.base)})patching: "adr x{adrrd}, {hex(default_ba_str_loc + self.base)}"')
        self.apply_patch(adroff, opcode3.to_bytes(4, byteorder='little'))
        return 0

    def get_change_reboot_to_fsboot_patch(self):
        logger = get_my_logger(self.verbose)
        rebootstr = self.memmem(b'reboot\x00')
        if rebootstr == -1:
            logger.error('Could not find rebootstr')
            return -1
        logger.debug(f'rebootstr={hex(rebootstr + self.base)}')
        rebootrefstr = self.iboot_memmem(rebootstr)
        if rebootrefstr == -1:
            logger.error('Could not find rebootrefstr')
            return -1
        logger.debug(f'rebootrefstr={hex(rebootrefstr + self.base)}')
        rebootref_ptr = rebootrefstr + 8
        logger.debug(f'rebootref_ptr={hex(rebootref_ptr + self.base)}')
        fsbootstr = self.memmem(b'fsboot\x00')
        if fsbootstr == -1:
            logger.error('Could not find fsbootstr')
            return -1
        logger.debug(f'fsbootstr={hex(fsbootstr + self.base)}')
        self.apply_patch(rebootrefstr, fsbootstr.to_bytes(4, byteorder='little'))
        fsbootrefstr = self.iboot_memmem(fsbootstr)
        if fsbootrefstr == -1:
            logger.error(f'Could not find fsbootrefstr')
            return -1
        logger.debug(f'fsbootrefstr={hex(fsbootrefstr + self.base)}')
        fsbootfunc = self.get_ptr_loc(fsbootrefstr + 8)
        logger.debug(f'fsbootfunc={hex(fsbootfunc)}')
        self.apply_patch(rebootrefstr + 8, (fsbootfunc - self.base).to_bytes(4, byteorder='little'))
        return 0

    def get_sigcheck_patch(self):
        logger = get_my_logger(self.verbose)
        img4decodemanifestexists = 0
        ios14 = False
        if ios14 := (self.vers >= 6671):
            if 8419 > self.vers >= 7459:
                img4decodemanifestexists = self.memmem(b'\xE8\x03\x00\xAA\xC0\x00\x80\x52\x28\x01\x00\xB4')
            else:
                img4decodemanifestexists = self.memmem(b'\xE8\x03\x00\xAA\xC0\x00\x80\x52\xE8\x00\x00\xB4')
        else:
            if (self.vers == 5540 and self.minor_vers >= 100) or self.vers > 5540:
                img4decodemanifestexists = self.memmem(b'\xE8\x03\x00\xAA\xC0\x00\x80\x52\xE8\x00\x00\xB4')
            elif (self.vers == 5540 and self.minor_vers <= 100) or (3406 <= self.vers <= 5540):
                img4decodemanifestexists = self.memmem(b'\xE8\x03\x00\xAA\xE0\x07\x1F\x32\xE8\x00\x00\xB4')
            else:
                logger.error(f'Unsupported iBoot (iBoot-{self.vers}.{self.minor_vers}), only iOS 10 or later iBoot is supported')
                return -1
        if img4decodemanifestexists == -1:
            logger.error(f'Could not find img4decodemanifestexists')
            return -1
        logger.debug(f'img4decodemanifestexists={hex(img4decodemanifestexists + self.base)}')
        img4decodemanifestexists_ref = self.xrefcode(img4decodemanifestexists)
        if img4decodemanifestexists_ref == 0:
            logger.error('Could not find img4decodemanifestexists_ref')
            return -1
        logger.debug(f'img4decodemanifestexists_ref={hex(img4decodemanifestexists_ref + self.base)}')
        adroff = self.step(img4decodemanifestexists_ref, self.size - img4decodemanifestexists_ref, 0x10000000, 0x9F000000)
        if insn.rd(self.get_insn(adroff), 'adr') != 2:
            adroff = self.step(img4decodemanifestexists_ref, self.size - adroff, 0x10000000, 0x9F000000)
            if insn.rd(self.get_insn(adroff), 'adr') != 2:
                logger.error('Could not find adroff')
                return -1
        img4interposercallback_ptr = insn.imm(adroff, self.get_insn(adroff), 'adr')
        if img4interposercallback_ptr == -1:
            logger.debug(f'Could not find img4interposercallback_ptr')
            return -1
        logger.debug(f'img4interposercallback_ptr={hex(int(img4interposercallback_ptr) + self.base)}')
        img4interposercallback = self.get_ptr_loc(img4interposercallback_ptr)
        real_img4interposercallback = img4interposercallback - self.base
        logger.debug(f'img4interposercallback={hex(img4interposercallback)}')
        real_img4interposercallback = self.step(real_img4interposercallback, self.size - real_img4interposercallback, 0xD65F03C0, 0xFFFFFFFF)
        img4interposercallback_ret = real_img4interposercallback
        if img4interposercallback_ret == 0:
            logger.error('Could not find img4interposercallback_ret')
            return -1
        logger.debug(f'img4interposercallback_ret={hex(img4interposercallback_ret + self.base)}')
        if not ios14:
            self.apply_patch(img4interposercallback_ret, b'\x00\x00\x80\xD2\xC0\x03\x5F\xD6')
            real_img4interposercallback += 4
            img4interposercallback_ret2 = self.step(real_img4interposercallback + 4, self.size - real_img4interposercallback, 0xD65F03C0, 0xFFFFFFFF)
            logger.debug(f'img4interposercallback_ret2={hex(img4interposercallback_ret2 + self.base)}')
            self.apply_patch(img4interposercallback_ret2 - 4, b'\x00\x00\x80\xD2')
        else:
            if self.step_back(real_img4interposercallback, 4, 0x91000000, 0xFF000000) != 0: # an add
                real_img4interposercallback = self.step_back(real_img4interposercallback - 8, real_img4interposercallback, 0xa94000f0, 0xfff000f0, reversed=True) # sill an ldp
                if insn.get_type(self.get_insn(real_img4interposercallback)) != 'mov':
                    real_img4interposercallback = self.step_back(real_img4interposercallback, real_img4interposercallback, 0x1f2003d5, 0xffffffff)
                img4interposercallback_mov = real_img4interposercallback
                if img4interposercallback_mov == 0:
                    logger.error('Could not find img4interposercallback_mov')
                    return -1
                logger.debug(f'img4interposercallback_mov={hex(img4interposercallback_mov + self.base)}')
                self.apply_patch(img4interposercallback_mov, b'\x00\x00\x80\xD2')
                retoff = self.step(real_img4interposercallback, self.size - real_img4interposercallback, 0xD65F03C0, 0xFFFFFFFF)
                img4interposercallback_ret2 = self.step(retoff + 4, self.size - retoff, 0xD65F03C0, 0xFFFFFFFF)
                if img4interposercallback_ret2 == 0:
                    logger.error('Could not find img4interposercallback_ret2')
                    return -1
                logger.debug(f'img4interposercallback_ret2={hex(img4interposercallback_ret2 + self.base)}')
                self.apply_patch(img4interposercallback_ret2 - 4, b'\x00\x00\x80\xD2')
            else:
                self.apply_patch(img4interposercallback_ret - 4, b'\x00\x00\x80\xD2')
                boff = self.step_back(real_img4interposercallback, real_img4interposercallback, 0x14000000, 0xFC000000)
                if self.step_back(boff, boff, 0xa94000f0, 0xfff000f0) == 0:
                    boff = self.step_back(real_img4interposercallback, real_img4interposercallback, 0x14000000, 0xFC000000)                
                    if self.step_back(boff, boff, 0xa94000f0, 0xfff000f0) == 0:
                        logger.error('img4interposercallback couldn\'t find branch for ret2')
                        return -1
                    else:
                        img4interposercallback_mov_x20 = self.step_back(boff, boff, 0xd2000000, 0xff000000)
                        logger.debug(f'img4interposercallback_mov_x20={hex(img4interposercallback_mov_x20 + self.base)}')
                        self.apply_patch(img4interposercallback_mov_x20, b'\x00\x00\x80\xD2')
        return 0

    def get_freshnonce_patch(self):
        logger = get_my_logger(self.verbose)
        # check stage first
        if self.stage1:
            logger.debug('iBootStage1/iBSS detected, not patching nvram')
            return 0
        noncevar_str = self.memmem(b'com.apple.System.boot-nonce\0')
        if noncevar_str == -1:
            logger.error('Could not find "com.apple.System.boot-nonce"')
            return -1
        logger.debug('Not iBootStage1/iBSS, continuing')
        logger.debug(f'noncevar_str={hex(noncevar_str + self.base)}')
        noncevar_ref = self.xref(noncevar_str)
        if noncevar_ref == 0:
            logger.error('Could not find noncevar_ref')
            return -1
        logger.debug(f'noncevar_ref={hex(noncevar_ref + self.base)}')
        noncefun1 = self.bof(noncevar_ref)
        if noncefun1 == 0:
            logger.error('Could not find noncefun1')
            return -1
        logger.debug(f'noncefun1={hex(noncefun1 + self.base)}')
        noncefun1_blref = self.xrefcode(noncefun1)
        if noncefun1_blref == 0:
            logger.error('Could not find noncefun1_blref')
            return -1
        logger.debug(f'noncefun1_blref={hex(noncefun1_blref + self.base)}')
        noncefun2 = self.bof(noncefun1_blref)
        if noncefun2 == 0:
            logger.error('Could not find noncefun2')
            return -1
        logger.debug(f'noncefun2={hex(noncefun2 + self.base)}')
        noncefun2_blref = self.xrefcode(noncefun2)
        if noncefun2_blref == 0:
            logger.error('Could not find noncefun2_blref')
            return -1
        logger.debug(f'noncefun2_blref={noncefun2_blref + self.base}')
        noncefun2_blref -= 4
        while insn.supertype(insn.get_type(self.get_insn(noncefun2_blref))) != 'sut_branch_imm':
            noncefun2_blref -= 4
        branch_loc = noncefun2_blref
        logger.debug(f'branch_loc={hex(branch_loc + self.base)}')
        self.apply_patch(branch_loc, b'\x1F\x20\x03\xD5')
        return 0

    @property
    def output(self):
        return bytes(self._buf)