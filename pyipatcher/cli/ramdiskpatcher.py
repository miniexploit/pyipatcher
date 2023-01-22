import click
from pyipatcher.patchfinder.asrpatchfinder import asrpatchfinder
from pyipatcher.patchfinder.rextpatchfinder import rextpatchfinder
from pyipatcher.patchfinder.patchfinder64 import patchfinder64
from pyipatcher.logger import get_my_logger

@click.command()
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
@click.option(
    '-a',
    '--asr',
    'is_asr',
    is_flag=True,
    help='Patch input file as an ASR (Patch signature check)'
)
@click.option(
    '-r',
    '--restored-external',
    'is_rext',
    is_flag=True,
    help='Patch input file as a restored_external (iOS 14 only) (Patch skip sealing system volume)'
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Show more debug information'
)

def ramdiskpatcher(input, output, is_asr, is_rext, verbose):
    logger = get_my_logger(verbose)
    data = input.read()
    apf = None
    rpf = None
    if is_asr:
        apf = asrpatchfinder(data, verbose)
        logger.info('Getting get_asr_sigcheck_patch()')
        if apf.get_asr_sigcheck_patch() == -1:
            logger.warning('Failed getting get_asr_sigcheck_patch()')
    elif is_rext:
        rpf = rextpatchfinder(data, verbose)
        logger.info('Getting get_skip_sealing_patch()')
        if rpf.get_skip_sealing_patch() == -1:
            logger.warning('Failed getting get_skip_sealing_patch()')
    logger.info(f'Writing out patched file to {output.name}')
    if apf:
        output.write(apf._buf)
    else:
        output.write(rpf._buf)
    return 0
    
