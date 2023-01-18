import click
from pyipatcher.patchfinder.asrpatchfinder import get_asr_patch
from pyipatcher.patchfinder.patchfinder64 import patchfinder64

@click.command()
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
def asrpatcher(input, output):
    asr = input.read()
    pf = patchfinder64(asr)
    print('Getting get_asr_patch()')
    get_asr_patch(pf)
    print(f'Writing out patched file to {output.name}')
    output.write(pf._buf)
    return 0