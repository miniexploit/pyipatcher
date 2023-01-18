import click
from pyipatcher.patchfinder.asrpatchfinder import get_asr_patch
from pyipatcher.patchfinder.patchfinder64 import patchfinder64
from pyipatcher.logger import get_my_logger

@click.command()
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
def asrpatcher(input, output):
    logger = get_my_logger('asrpatcher')
    asr = input.read()
    pf = patchfinder64(asr)
    logger.info('Getting get_asr_patch()')
    get_asr_patch(pf)
    logger.info(f'Writing out patched file to {output.name}')
    output.write(pf._buf)
    return 0