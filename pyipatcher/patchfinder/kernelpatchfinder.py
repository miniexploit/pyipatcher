from .patchfinder64 import patchfinder64

kernel_vers = 0

def retassure(cond, errmsg):
    if not cond:
        raise Exception(errmsg)

def assure(cond):
    retassure(cond, "assure failed")

def print_help():
    print("Usage: kernelpatcher [input] [output] [args]")
    print("\t-a\t\tPatch AMFI")
    print("\t-e\t\tPatch root volume seal is broken (iOS 15 Only)")
    print("\t-u\t\tPatch update_rootfs_rw_patch (iOS 15 Only)")

def get_amfi_out_of_my_way_patch(pf):    
    amfi_str = b"entitlements too small"
    if kernel_vers >= 7938:
        amfi_str = b"Internal Error: No cdhash found."
    ent_loc = pf.memmem(amfi_str)
    retassure(ent_loc != -1, "get_amfi_out_of_my_way_patch: Could not find amfi_str")
    print(f"get_amfi_out_of_my_way_patch: Found amfi_str loc at {hex(ent_loc)}")
    ent_ref = pf.xref(0, pf.size, ent_loc)
    retassure(ent_ref != 0, "get_amfi_out_of_my_way_patch: Could not find amfi_str xref")
    print(f"get_amfi_out_of_my_way_patch: Found amfi_str ref at {hex(ent_ref)}")
    next_bl = pf.step(ent_ref, 100, 0x94000000, 0xFC000000)
    assure(next_bl != 0)
    next_bl = pf.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
    assure(next_bl != 0)
    if kernel_vers > 3789:
        next_bl = pf.step(next_bl+0x4, 200, 0x94000000, 0xFC000000)
        assure(next_bl != 0)
    function = pf.follow_call(next_bl)
    retassure(function != 0, "get_amfi_out_of_my_way_patch: Could not find function bl")
    print(f"get_amfi_out_of_my_way_patch: Patching AMFI at {hex(function)}")
    pf.apply_patch(function, b"\xe0\x03\x002")
    pf.apply_patch(function+4, b"\xc0\x03_\xd6")
    return 0

def get_root_volume_seal_is_broken_patch(pf):
    roothash_authenticated_string = b"\"root volume seal is broken %p\\n\""
    roothash_authenticated_loc = pf.memmem(roothash_authenticated_string)
    retassure(roothash_authenticated_loc != -1, "get_root_volume_seal_is_broken_patch: Could not find roothash_authenticated_string")
    print(f"get_root_volume_seal_is_broken_patch: Found roothash_authenticated_string loc at {hex(roothash_authenticated_loc)}")
    roothash_authenticated_ref = pf.xref(0, pf.size, roothash_authenticated_loc)
    retassure(roothash_authenticated_ref != 0, "get_root_volume_seal_is_broken_patch: Could not find roothash_authenticated_string xref")
    print(f"get_root_volume_seal_is_broken_patch: Found roothash_authenticated_string ref at {hex(roothash_authenticated_ref)}")
    tbnz_ref = pf.step_back(roothash_authenticated_ref, 80, 0x36000000, 0x7E000000)
    assure(tbnz_ref != 0)
    print(f"get_root_volume_seal_is_broken_patch: Patching tbnz at {hex(tbnz_ref)}")
    pf.apply_patch(tbnz_ref, b"\x1f \x03\xd5")
    return 0

def get_update_rootfs_rw_patch(pf):
    update_rootfs_rw_string = b"%s:%d: %s Updating mount to read/write mode is not allowed"
    update_rootfs_rw_loc = pf.memmem(update_rootfs_rw_string)
    retassure(update_rootfs_rw_loc != -1, "get_update_rootfs_rw_patch: Could not find update_rootfs_rw_string")
    print(f"get_update_rootfs_rw_patch: Found update_rootfs_rw_string loc at {hex(update_rootfs_rw_loc)}")
    update_rootfs_rw_ref = pf.xref(0, pf.size, update_rootfs_rw_loc)
    print(f"get_update_rootfs_rw_patch: Found update_rootfs_rw_string ref at {hex(update_rootfs_rw_ref)}")
    tbnz_ref = pf.step_back(update_rootfs_rw_ref, 800, 0x36000000, 0x7E000000)
    assure(tbnz_ref != 0)
    tbnz_ref2 = pf.step_back(tbnz_ref - 4, 800, 0x36000000, 0x7E000000)
    assure(tbnz_ref != 0)
    print(f"get_update_rootfs_rw_patch: Patching tbnz at {hex(tbnz_ref2)}")
    pf.apply_patch(tbnz_ref2, b"\x1f \x03\xd5")
    return 0