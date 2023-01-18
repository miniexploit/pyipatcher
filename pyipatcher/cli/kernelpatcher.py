import click
from pyipatcher.patchfinder.patchfinder64 import patchfinder64
import pyipatcher.patchfinder.kernelpatchfinder as kpf
from pyipatcher.logger import get_my_logger

kernel_vers = 0

@click.command()
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
@click.option(
    '-a',
    '--amfi',
    'patch_amfi',
    is_flag=True,
    help='Patch AMFI'
)
@click.option(
    '-e',
    '--rootvol-seal',
    'rootvol_seal',
    is_flag=True,
    help='Patch root volume seal is broken (iOS 15 Only)'
)
@click.option(
    '-u',
    '--update-rootfs-rw',
    'update_rootfs_rw',
    is_flag=True,
    help='Patch update_rootfs_rw (iOS 15 Only)'
)

@click.option(
    '-f',
    '--afu-img4-sigcheck',
    'afu_img4_sigpatch',
    is_flag=True,
    help='Patch AppleFirmwareUpdate img4 signature check'
)

def kernelpatcher(input, output, patch_amfi, rootvol_seal, update_rootfs_rw, afu_img4_sigpatch):
    logger = get_my_logger('kernelpatcher')
    kernel = input.read()
    if kernel[:4] == b'\xca\xfe\xba\xbe':
        logger.info('Detected fat macho kernel')
        kernel = kernel[28:]
    pf = patchfinder64(kernel)
    xnu = pf.get_str(b"root:xnu-", 4, end=True)
    global kernel_vers
    kernel_vers = int(xnu)
    logger.info(f'Kernel-{kernel_vers} inputted')
    if patch_amfi:
        logger.info('Getting get_amfi_out_of_my_way_patch()')
        if kpf.get_amfi_out_of_my_way_patch(pf) == -1:
            logger.warning('Failed getting get_amfi_out_of_my_way_patch()')
            return -1
    if rootvol_seal:
        logger.info('Getting get_root_volume_seal_is_broken_patch()')
        if kpf.get_root_volume_seal_is_broken_patch(pf) == -1:
            logger.warning('Failed getting get_root_volume_seal_is_broken_patch()')
    if update_rootfs_rw:
        logger.info('Getting get_update_rootfs_rw_patch()')
        if kpf.get_update_rootfs_rw_patch(pf) == -1:
            logger.warning('Failed getting get_update_roofs_rw_patch()')
    if afu_img4_sigpatch:
        logger.info('Getting get_AFU_img4_sigcheck_patch()')
        if kpf.get_AFU_img4_sigcheck_patch(pf) == -1:
            logger.warning('Failed getting get_AFU_img4_sigcheck_patch()')
    logger.info(f'Writing out patched file to {output.name}')
    output.write(pf._buf)
