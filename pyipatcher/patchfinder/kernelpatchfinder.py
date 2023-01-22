from .patchfinder64 import patchfinder64
from pyipatcher.logger import get_my_logger

class kernelpatchfinder(patchfinder64):
    def __init__(self, buf: bytes, verbose: bool):
        super().__init__(buf)
        self.kvers = 0
        self.verbose = verbose

    @property
    def kernel_vers(self):
        if self.kvers:
            return self.kvers
        xnu = self.get_str(b"root:xnu-", 4, end=True)
        self.kvers = int(xnu)
        return self.kvers
    
    def get_amfi_patch(self):
        logger = get_my_logger(self.verbose)
        amfi_str = b"entitlements too small"
        if self.kernel_vers >= 7938:
            amfi_str = b"Internal Error: No cdhash found."
        logger.debug(f'amfi_str={amfi_str.decode()}')
        ent_loc = self.memmem(amfi_str)
        if ent_loc == -1:
            logger.error('Could not find amfi_str')
            return -1
        logger.debug(f'Found amfi_str loc at {hex(ent_loc)}')
        ent_ref = self.xref(ent_loc)
        if ent_ref == 0:
            logger.error('Could not find amfi_str xref')
            return -1
        logger.debug(f'Found amfi_str ref at {hex(ent_ref)}')
        next_bl = self.step(ent_ref, 100, 0x94000000, 0xFC000000)
        if next_bl == 0:
            logger.error('Could not find next bl')
            return -1
        next_bl = self.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
        if next_bl == 0:
            logger.error('Could not find next bl')
            return -1
        if self.kernel_vers > 3789:
            next_bl = self.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
            if next_bl == 0:
                logger.error('Could not find next bl')
                return -1
        function = self.follow_call(next_bl)
        if function == 0: 
            logger.error("Could not find function bl")
            return -1
        logger.debug(f'Patching AMFI at {hex(function)}')
        self.apply_patch(function, b'\xe0\x03\x002\xc0\x03_\xd6')
        return 0

    def get_root_volume_seal_is_broken_patch(self):
        logger = get_my_logger(self.verbose)
        roothash_authenticated_string = b"\"root volume seal is broken %p\\n\""
        roothash_authenticated_loc = self.memmem(roothash_authenticated_string)
        if roothash_authenticated_loc == -1:
            logger.error('Could not find roothash_authenticated_string')
            return -1
        logger.debug(f'Found roothash_authenticated_string loc at {hex(roothash_authenticated_loc)}')
        roothash_authenticated_ref = self.xref(roothash_authenticated_loc)
        if roothash_authenticated_ref == 0: 
            logger.error('Could not find roothash_authenticated_string xref')
            return -1
        logger.debug(f'Found roothash_authenticated_string ref at {hex(roothash_authenticated_ref)}')
        tbnz_ref = self.step_back(roothash_authenticated_ref, 80, 0x36000000, 0x7E000000)
        if tbnz_ref == 0:
            logger.error('Could not find tbnz ref')
            return -1
        logger.debug(f'Patching tbnz at {hex(tbnz_ref)}')
        self.apply_patch(tbnz_ref, b"\x1f \x03\xd5")
        return 0

    def get_update_rootfs_rw_patch(self):
        logger = get_my_logger(self.verbose)
        update_rootfs_rw_string = b"%s:%d: %s Updating mount to read/write mode is not allowed"
        update_rootfs_rw_loc = self.memmem(update_rootfs_rw_string)
        if update_rootfs_rw_loc == -1: 
            logger.error('Could not find update_rootfs_rw_string')
            return -1
        logger.debug(f'Found update_rootfs_rw_string loc at {hex(update_rootfs_rw_loc)}')
        update_rootfs_rw_ref = self.xref(update_rootfs_rw_loc)
        logger.debug(f'Found update_rootfs_rw_string ref at {hex(update_rootfs_rw_ref)}')
        tbnz_ref = self.step_back(update_rootfs_rw_ref, 800, 0x36000000, 0x7E000000)
        if tbnz_ref == 0:
            logger.error('Could not find tbnz ref')
            return -1
        tbnz_ref2 = self.step_back(tbnz_ref - 4, 800, 0x36000000, 0x7E000000)
        if tbnz_ref2 == 0:
            logger.error('Could not find tbnz ref')
            return -1
        logger.debug(f'Patching tbnz at {hex(tbnz_ref2)}')
        self.apply_patch(tbnz_ref2, b'\x1f \x03\xd5')
        return 0

    def get_update_rootfs_rw_patch(self):
        logger = get_my_logger(self.verbose)
        update_rootfs_rw_string = b"%s:%d: %s Updating mount to read/write mode is not allowed"
        update_rootfs_rw_loc = self.memmem(update_rootfs_rw_string)
        if update_rootfs_rw_loc == -1: 
            logger.error('Could not find update_rootfs_rw_string')
            return -1
        logger.debug(f'Found update_rootfs_rw_string loc at {hex(update_rootfs_rw_loc)}')
        update_rootfs_rw_ref = self.xref(update_rootfs_rw_loc)
        logger.debug(f'Found update_rootfs_rw_string ref at {hex(update_rootfs_rw_ref)}')
        tbnz_ref = self.step_back(update_rootfs_rw_ref, 800, 0x36000000, 0x7E000000)
        if tbnz_ref == 0:
            logger.error('Could not find tbnz ref')
            return -1
        tbnz_ref2 = self.step_back(tbnz_ref - 4, 800, 0x36000000, 0x7E000000)
        if tbnz_ref2 == 0:
            logger.error('Could not find tbnz ref')
            return -1
        logger.debug(f'Patching tbnz at {hex(tbnz_ref2)}')
        self.apply_patch(tbnz_ref2, b'\x1f \x03\xd5')
        return 0

    def get_AFU_img4_sigcheck_patch(self):
        logger = get_my_logger(self.verbose)
        ent_loc = self.memmem(b'%s::%s() Performing img4 validation outside of workloop')
        if ent_loc == -1:
            logger.error('Could not find \"%s::%s() Performing img4 validation outside of workloop\" str')
            return -1
        logger.debug(f'"\%s::%s() Performing img4 validation outside of workloop\" str loc at {hex(ent_loc)}')
        ent_ref = self.xref(ent_loc)
        if ent_ref == 0:
            logger.error('Could not find \"%s::%s() Performing img4 validation outside of workloop\" str ref')
            return -1
        logger.debug(f'\"%s::%s() Performing img4 validation outside of workloop\" str ref at {hex(ent_ref)}')
        logger.debug(f'Patching str ref')
        self.apply_patch(ent_ref + 12, b'\x00\x00\x80\xd2')
        return 0




