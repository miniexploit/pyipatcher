import click
from pyipatcher.patchfinder.asrpatchfinder import get_asr_patch

@click.command()
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
def asrpatcher(input, output):
    pf = patchfinder64(asr)
    asr = input.read()
    print('Getting get_asr_patch()')
    get_asr_patch(asr)
    print(f'Writing out patched file to {output.name}')
    output.write(pf._buf)
    return 0