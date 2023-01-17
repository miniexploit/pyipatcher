from .patchfinder64 import patchfinder64, arm64_branch_instruction
import ctypes

def retassure(cond, errmsg):
    if not cond:
        raise Exception(errmsg)

def assure(cond):
    retassure(cond, "assure failed")

def get_asr_patch(pf):
    failed = pf.memmem(b"Image failed signature verification")
    retassure(failed != -1, "Could not find failed message")
    print(f"\"Image failed signature verification\" at {hex(failed)}")
    passed = pf.memmem(b"Image passed signature verification")
    retassure(passed != -1, "Could not find passed message")
    print(f"\"Image failed signature verification\" at {hex(passed)}")
    ref_failed = pf.xref(0, pf.size, failed)
    ref_passed = pf.xref(0, pf.size, passed)
    assure(ref_failed)
    assure(ref_passed)
    our_branch = arm64_branch_instruction(ref_failed, ref_passed)
    pf.apply_patch(ref_failed, our_branch.to_bytes(4, byteorder='little'))