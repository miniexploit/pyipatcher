from .patchfinder64 import patchfinder64
from pyipatcher.logger import get_my_logger

kernel_vers = 0

def retassure(cond, errmsg):
    if not cond:
        raise Exception(errmsg)

def assure(cond):
    retassure(cond, "assure failed")

def get_amfi_out_of_my_way_patch(pf):    
    logger = get_my_logger('get_amfi_out_of_my_way_patch')
    amfi_str = b"entitlements too small"
    if kernel_vers >= 7938:
        amfi_str = b"Internal Error: No cdhash found."
    ent_loc = pf.memmem(amfi_str)
    retassure(ent_loc != -1, "Could not find amfi_str")
    logger.debug(f'get_amfi_out_of_my_way_patch: Found amfi_str loc at {hex(ent_loc)}')
    ent_ref = pf.xref(0, pf.size, ent_loc)
    retassure(ent_ref != 0, "get_amfi_out_of_my_way_patch: Could not find amfi_str xref")
    logger.debug(f'Found amfi_str ref at {hex(ent_ref)}')
    next_bl = pf.step(ent_ref, 100, 0x94000000, 0xFC000000)
    assure(next_bl != 0)
    next_bl = pf.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
    assure(next_bl != 0)
    if kernel_vers > 3789:
        next_bl = pf.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
        assure(next_bl != 0)
    function = pf.follow_call(next_bl)
    retassure(function != 0, "Could not find function bl")
    logger.debug(f'Patching AMFI at {hex(function)}')
    pf.apply_patch(function, b"\xe0\x03\x002")
    pf.apply_patch(function+4, b"\xc0\x03_\xd6")
    return 0

def get_root_volume_seal_is_broken_patch(pf):
    logger = get_my_logger('get_root_volume_seal_is_broken_patch')
    roothash_authenticated_string = b"\"root volume seal is broken %p\\n\""
    roothash_authenticated_loc = pf.memmem(roothash_authenticated_string)
    retassure(roothash_authenticated_loc != -1, "Could not find roothash_authenticated_string")
    logger.debug(f'Found roothash_authenticated_string loc at {hex(roothash_authenticated_loc)}')
    roothash_authenticated_ref = pf.xref(0, pf.size, roothash_authenticated_loc)
    retassure(roothash_authenticated_ref != 0, "Could not find roothash_authenticated_string xref")
    logger.debug(f'Found roothash_authenticated_string ref at {hex(roothash_authenticated_ref)}')
    tbnz_ref = pf.step_back(roothash_authenticated_ref, 80, 0x36000000, 0x7E000000)
    assure(tbnz_ref != 0)
    logger.debug(f'Patching tbnz at {hex(tbnz_ref)}')
    pf.apply_patch(tbnz_ref, b"\x1f \x03\xd5")
    return 0

def get_update_rootfs_rw_patch(pf):
    logger = get_my_logger('get_update_rootfs_rw_patch')
    update_rootfs_rw_string = b"%s:%d: %s Updating mount to read/write mode is not allowed"
    update_rootfs_rw_loc = pf.memmem(update_rootfs_rw_string)
    retassure(update_rootfs_rw_loc != -1, "Could not find update_rootfs_rw_string")
    logger.debug(f'Found update_rootfs_rw_string loc at {hex(update_rootfs_rw_loc)}')
    update_rootfs_rw_ref = pf.xref(0, pf.size, update_rootfs_rw_loc)
    logger.debug(f'Found update_rootfs_rw_string ref at {hex(update_rootfs_rw_ref)}')
    tbnz_ref = pf.step_back(update_rootfs_rw_ref, 800, 0x36000000, 0x7E000000)
    assure(tbnz_ref != 0)
    tbnz_ref2 = pf.step_back(tbnz_ref - 4, 800, 0x36000000, 0x7E000000)
    assure(tbnz_ref != 0)
    logger.debug(f'Patching tbnz at {hex(tbnz_ref2)}')
    pf.apply_patch(tbnz_ref2, b"\x1f \x03\xd5")
    return 0