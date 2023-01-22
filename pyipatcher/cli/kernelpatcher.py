import click
from pyipatcher.patchfinder.kernelpatchfinder import kernelpatchfinder
from pyipatcher.logger import get_my_logger

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

@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Show more debug information'
)

def kernelpatcher(input, output, patch_amfi, rootvol_seal, update_rootfs_rw, afu_img4_sigpatch, verbose):
    logger = get_my_logger(verbose)
    kernel = input.read()
    if kernel[:4] == b'\xca\xfe\xba\xbe':
        logger.info('Detected fat macho kernel')
        kernel = kernel[28:]
    kpf = kernelpatchfinder(kernel, verbose)
    logger.info(f'Kernel-{kpf.kernel_vers} inputted')
    if patch_amfi:
        logger.info('Getting get_amfi_patch()')
        if kpf.get_amfi_patch() == -1:
            logger.warning('Failed getting get_amfi_patch()')
            return -1
    if rootvol_seal:
        logger.info('Getting get_root_volume_seal_is_broken_patch()')
        if kpf.get_root_volume_seal_is_broken_patch() == -1:
            logger.warning('Failed getting get_root_volume_seal_is_broken_patch()')
    if update_rootfs_rw:
        logger.info('Getting get_update_rootfs_rw_patch()')
        if kpf.get_update_rootfs_rw_patch() == -1:
            logger.warning('Failed getting get_update_roofs_rw_patch()')
    if afu_img4_sigpatch:
        logger.info('Getting get_AFU_img4_sigcheck_patch()')
        if kpf.get_AFU_img4_sigcheck_patch() == -1:
            logger.warning('Failed getting get_AFU_img4_sigcheck_patch()')
    logger.info(f'Writing out patched file to {output.name}')
    output.write(kpf._buf)
