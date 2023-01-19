from .patchfinder64 import patchfinder64, arm64_branch_instruction
import ctypes
from pyipatcher.logger import get_my_logger

def get_asr_patch(pf):
    logger = get_my_logger('get_asr_patch')
    failed = pf.memmem(b"Image failed signature verification")
    if failed == -1: 
        logger.error('Could not find \"Image failed signature verification\"')
        return -1
    logger.debug(f"\"Image failed signature verification\" at {hex(failed)}")
    passed = pf.memmem(b"Image passed signature verification")
    if passed == -1: 
        logger.error('Could not find \"Image passed signature verification\"')
        return -1
    logger.debug(f"\"Image failed signature verification\" at {hex(passed)}")
    ref_failed = pf.xref(0, pf.size, failed)
    ref_passed = pf.xref(0, pf.size, passed)
    if ref_failed == 0:
        logger.error('Could not find \"Image failed signature verification\" ref')
        return -1
    if ref_passed == 0:
        logger.error('Could not find \"Image passed signature verification\" ref')
        return -1
    our_branch = arm64_branch_instruction(ref_failed, ref_passed)
    pf.apply_patch(ref_failed, our_branch.to_bytes(4, byteorder='little'))