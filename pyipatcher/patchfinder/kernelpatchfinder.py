from .patchfinder64 import patchfinder64
from pyipatcher.logger import get_my_logger

kernel_vers = 0

def get_amfi_out_of_my_way_patch(pf):    
    logger = get_my_logger('get_amfi_out_of_my_way_patch')
    amfi_str = b"entitlements too small"
    if kernel_vers >= 7938:
        amfi_str = b"Internal Error: No cdhash found."
    ent_loc = pf.memmem(amfi_str)
    if ent_loc == -1:
        logger.error('Could not find amfi_str')
        return -1
    logger.debug(f'Found amfi_str loc at {hex(ent_loc)}')
    ent_ref = pf.xref(0, pf.size, ent_loc)
    if ent_ref == 0:
        logger.error('Could not find amfi_str xref')
        return -1
    logger.debug(f'Found amfi_str ref at {hex(ent_ref)}')
    next_bl = pf.step(ent_ref, 100, 0x94000000, 0xFC000000)
    if next_bl == 0:
        logger.error('Could not find next bl')
        return -1
    next_bl = pf.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
    if next_bl == 0:
        logger.error('Could not find next bl')
        return -1
    if kernel_vers > 3789:
        next_bl = pf.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
        if next_bl == 0:
            logger.error('Could not find next bl')
            return -1
    function = pf.follow_call(next_bl)
    if function == 0: 
        logger.error("Could not find function bl")
        return -1
    logger.debug(f'Patching AMFI at {hex(function)}')
    pf.apply_patch(function, b"\xe0\x03\x002")
    pf.apply_patch(function+4, b"\xc0\x03_\xd6")
    return 0

def get_root_volume_seal_is_broken_patch(pf):
    logger = get_my_logger('get_root_volume_seal_is_broken_patch')
    roothash_authenticated_string = b"\"root volume seal is broken %p\\n\""
    roothash_authenticated_loc = pf.memmem(roothash_authenticated_string)
    if roothash_authenticated_loc == -1:
        logger.error('Could not find roothash_authenticated_string')
        return -1
    logger.debug(f'Found roothash_authenticated_string loc at {hex(roothash_authenticated_loc)}')
    roothash_authenticated_ref = pf.xref(0, pf.size, roothash_authenticated_loc)
    if roothash_authenticated_ref == 0: 
        logger.error('Could not find roothash_authenticated_string xref')
        return -1
    logger.debug(f'Found roothash_authenticated_string ref at {hex(roothash_authenticated_ref)}')
    tbnz_ref = pf.step_back(roothash_authenticated_ref, 80, 0x36000000, 0x7E000000)
    if tbnz_ref == 0:
        logger.error('Could not find tbnz ref')
        return -1
    logger.debug(f'Patching tbnz at {hex(tbnz_ref)}')
    pf.apply_patch(tbnz_ref, b"\x1f \x03\xd5")
    return 0

def get_update_rootfs_rw_patch(pf):
    logger = get_my_logger('get_update_rootfs_rw_patch')
    update_rootfs_rw_string = b"%s:%d: %s Updating mount to read/write mode is not allowed"
    update_rootfs_rw_loc = pf.memmem(update_rootfs_rw_string)
    if update_rootfs_rw_loc == -1: 
        logger.error('Could not find update_rootfs_rw_string')
        return -1
    logger.debug(f'Found update_rootfs_rw_string loc at {hex(update_rootfs_rw_loc)}')
    update_rootfs_rw_ref = pf.xref(0, pf.size, update_rootfs_rw_loc)
    logger.debug(f'Found update_rootfs_rw_string ref at {hex(update_rootfs_rw_ref)}')
    tbnz_ref = pf.step_back(update_rootfs_rw_ref, 800, 0x36000000, 0x7E000000)
    if tbnz_ref == 0:
        logger.error('Could not find tbnz ref')
        return -1
    tbnz_ref2 = pf.step_back(tbnz_ref - 4, 800, 0x36000000, 0x7E000000)
    if tbnz_ref2 == 0:
        logger.error('Could not find tbnz ref')
        return -1
    logger.debug(f'Patching tbnz at {hex(tbnz_ref2)}')
    pf.apply_patch(tbnz_ref2, b'\x1f \x03\xd5')
    return 0

def get_AFU_img4_sigcheck_patch(pf):
    logger = get_my_logger('get_AFU_img4_sigcheck_patch')
    ent_loc = pf.memmem(b'%s::%s() Performing img4 validation outside of workloop')
    if ent_loc == -1:
        logger.error('Could not find \"%s::%s() Performing img4 validation outside of workloop\" str')
        return -1
    logger.debug(f'"\%s::%s() Performing img4 validation outside of workloop\" str loc at {hex(ent_loc)}')
    ent_ref = pf.xref(0, pf.size, ent_loc)
    if ent_ref == 0:
        logger.error('Could not find \"%s::%s() Performing img4 validation outside of workloop\" str ref')
        return -1
    logger.debug(f'\"%s::%s() Performing img4 validation outside of workloop\" str ref at {hex(ent_ref)}')
    logger.debug(f'Patching str ref')
    pf.apply_patch(ent_ref + 12, b'\x00\x00\x80\xd2')
    return 0
    
    pf.apply_patch(tbnz_ref2, b"\x1f \x03\xd5")
    return 0