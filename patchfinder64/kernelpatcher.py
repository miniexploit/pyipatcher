#!/usr/bin/env python3

import sys

from m1n1Exception import *

from patchfinder64 import PatchFinder64

set_package_name("kernelpatcher")
kernel_vers = 0


def assure(cond):
    retassure(cond, "assure failed")


def print_help():
    print("Usage: kernelpatcher [input] [output] [args]")
    print("\t-a\t\tPatch AMFI")
    print("\t-e\t\tPatch root volume seal is broken (iOS 15 Only)")


def get_amfi_out_of_my_way_patch(pf):
    amfi_str = b"entitlements too small"
    string_len = 22
    if kernel_vers >= 7938:
        amfi_str = b"Internal Error: No cdhash found."
        string_len = 32
    ent_loc = pf.memmem(amfi_str)
    retassure(ent_loc != 0, "get_amfi_out_of_my_way_patch: Could not find amfi_str")
    print(f"get_amfi_out_of_my_way_patch: Found amfi_str loc at {hex(ent_loc)}")
    ent_ref = pf.xref(0, pf.size, ent_loc)
    retassure(
        ent_ref != 0, "get_amfi_out_of_my_way_patch: Could not find amfi_str xref"
    )
    print(f"get_amfi_out_of_my_way_patch: Found amfi_str ref at {hex(ent_ref)}")
    next_bl = pf.step(ent_ref, 100, 0x94000000, 0xFC000000)
    assure(next_bl != 0)
    next_bl = pf.step(next_bl + 0x4, 200, 0x94000000, 0xFC000000)
    assure(next_bl != 0)
    if kernel_vers > 3789:
        next_bl = pf.step(next_bl + 0x4, 200, 0x94000000, 0xFC000000)
        assure(next_bl != 0)
    function = pf.follow_call(next_bl)
    retassure(function != 0, "get_amfi_out_of_my_way_patch: Could not find function bl")
    print(f"get_amfi_out_of_my_way_patch: Patching AMFI at {hex(function)}")
    pf.apply_patch(function, b"\xe0\x03\x002")
    pf.apply_patch(function + 4, b"\xc0\x03_\xd6")
    return 0


def get_root_volume_seal_is_broken_patch(pf):
    roothash_authenticated_string = b"\"root volume seal is broken %p\\n\""
    roothash_authenticated_loc = pf.memmem(roothash_authenticated_string)
    retassure(
        roothash_authenticated_loc != 0,
        "get_root_volume_seal_is_broken_patch: Could not find roothash_authenticated_string",
    )
    print(
        f"get_root_volume_seal_is_broken_patch: Found roothash_authenticated_string loc at {hex(roothash_authenticated_loc)}"
    )
    roothash_authenticated_ref = pf.xref(0, pf.size, roothash_authenticated_loc)
    retassure(
        roothash_authenticated_ref != 0,
        "get_root_volume_seal_is_broken_patch: Could not find roothash_authenticated_string xref",
    )
    print(
        f"get_root_volume_seal_is_broken_patch: Found roothash_authenticated_string ref at {hex(roothash_authenticated_ref)}"
    )
    tbnz_ref = pf.step_back(roothash_authenticated_ref, 80, 0x36000000, 0x7E000000)
    assure(tbnz_ref != 0)
    print(f"get_root_volume_seal_is_broken_patch: Found tbnz at {hex(tbnz_ref)}")
    print(f"get_root_volume_seal_is_broken_patch: Patching tbnz at {hex(tbnz_ref)}")
    pf.apply_patch(tbnz_ref, b"\x1f \x03\xd5")
    return 0


def main():
    if len(sys.argv) <= 3:
        print_help()
        sys.exit(0)
    kernel = open(sys.argv[1], "rb").read()
    if kernel[0:4] == b"\xca\xfe\xba\xbe":
        print("Detected fat macho kernel")
        kernel = kernel[28:]

    pf = patchfinder64(kernel)
    xnu = pf.get_str(b"root:xnu-", 4, end=True)
    global kernel_vers
    kernel_vers = int(xnu)
    print(f"Kernel-{kernel_vers} inputted")
    for arg in sys.argv:
        if arg == "-a":
            print("Getting get_amfi_out_of_my_way_patch()")
            get_amfi_out_of_my_way_patch(pf)
        if arg == "-e":
            print("Getting get_root_volume_seal_is_broken_patch()")
            get_root_volume_seal_is_broken_patch(pf)

    print("Writing out patched file")
    with open(sys.argv[2], "wb") as f:
        f.write(pf._buf)


if __name__ == '__main__':
    try:
        main()
    except m1n1Exception as e:
        print(e)
