#!/usr/bin/env python3

# TODO: docstrings


import sys
from typing import BinaryIO

import click

from patchfinder64 import patchfinder64, __version__


def amfi_patch(pf64: patchfinder64, xnu_ver: int, verbose: bool) -> None:
    if xnu_ver >= 7938:
        amfi_str = b'Internal Error: No cdhash found.'
    else:
        amfi_str = b'entitlements too small'

    if verbose:
        click.echo(f"[DEBUG] Searching for '{amfi_str.decode()}' string...")

    amfi_str_loc = pf64.memmem(amfi_str)
    if amfi_str_loc == 0:
        click.secho(
            f"[ERROR] Could not find '{amfi_str.decode()}' string. Exiting."
            if verbose
            else '[ERROR] Failed to patch AppleMobileFileIntegrity.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{amfi_str.decode()}' string at {hex(amfi_str_loc)}."
        )

    amfi_xref = pf64.xref(0, len(pf64), amfi_str_loc)
    if amfi_xref == 0:
        click.secho(
            f"[ERROR] Could not find '{amfi_str.decode()}' string reference. Exiting."
            if verbose
            else '[ERROR] Failed to patch AppleMobileFileIntegrity.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{amfi_str.decode()}' string xref at {hex(amfi_xref)}."
        )

    for i in range(2 if xnu_ver > 3789 else 3):
        next_bl = pf64.step(
            next_bl if i == 0 else next_bl + 0x4, 200, 0x94000000, 0xFC000000
        )
        if next_bl == 0:
            click.secho(
                '[ERROR] Could not find next bl.'
                if verbose
                else '[ERROR] Failed to patch AppleMobileFileIntegrity.',
                fg='red',
            )
            return

        elif verbose:
            click.echo(f'[DEBUG] Found next bl at {hex(next_bl)}')

    function = pf64.follow_call(next_bl)
    if function == 0:
        click.secho(
            '[ERROR] Could not find function to patch.'
            if verbose
            else '[ERROR] Failed to patch AppleMobileFileIntegrity.',
            fg='red',
        )
        return

    if verbose:
        click.echo(f'[DEBUG] Patching AppleMobileFileIntegrity at {hex(function)}.')
    pf64.apply_patch(function, b'\xe0\x03\x002\xc0\x03_\xd6', length=8)


@click.command()
@click.version_option(message=f'Criptam {__version__}')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input kernelcache file.',
)
@click.option(
    '-o',
    '--output',
    'output',
    type=click.File('wb'),
    required=True,
    help='File to output patched kernelcache to.',
)
@click.option(
    '-a',
    '--patch-amfi',
    'patch_amfi',
    is_flag=True,
    help='Patch AppleMobileFileIntegrity.',
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def main(input_: BinaryIO, output: BinaryIO, patch_amfi: bool, verbose: bool) -> None:
    if not verbose:
        sys.tracebacklimit = 0

    click.echo(f'Reading {input_.name}...')
    data = input_.read()

    if data[:4] == b'\xca\xfe\xba\xbe':
        click.echo('[NOTE] Detected fat macho kernel.')
        data = data[28:]

    pf64 = patchfinder64(data)
    xnu_ver = int(pf64.get_str(b'root:xnu-', 4, end=True))
    if verbose:
        click.echo(f'[DEBUG] Kernel version: {xnu_ver}')

    if patch_amfi:
        click.echo('Patching AppleMobileFileIntegrity...')
        amfi_patch(pf64, xnu_ver, verbose)

    click.echo(f'Writing patched kernel to {output.name}...')
    output.write(pf64.data)

    # def get_root_volume_seal_is_broken_patch(pf64):
    # roothash_authenticated_string = b'\'root volume seal is broken %p\\n\''
    # roothash_authenticated_loc = pf64.memmem(roothash_authenticated_string)
    # retassure(
    #    roothash_authenticated_loc != 0,
    #    'get_root_volume_seal_is_broken_patch: Could not find roothash_authenticated_string',
    # )
    # print(
    #    f'get_root_volume_seal_is_broken_patch: Found roothash_authenticated_string loc at {hex(roothash_authenticated_loc)}'
    # )
    # roothash_authenticated_ref = pf64.xref(0, pf64.size, roothash_authenticated_loc)
    # retassure(
    #    roothash_authenticated_ref != 0,
    #    'get_root_volume_seal_is_broken_patch: Could not find roothash_authenticated_string xref',
    # )
    # print(
    #    f'get_root_volume_seal_is_broken_patch: Found roothash_authenticated_string ref at {hex(roothash_authenticated_ref)}'
    # )
    # tbnz_ref = pf64.step_back(roothash_authenticated_ref, 80, 0x36000000, 0x7E000000)
    # assure(tbnz_ref != 0)
    # print(f'get_root_volume_seal_is_broken_patch: Found tbnz at {hex(tbnz_ref)}')
    # print(f'get_root_volume_seal_is_broken_patch: Patching tbnz at {hex(tbnz_ref)}')
    # pf64.apply_patch(tbnz_ref, b'\x1f \x03\xd5')
    # return 0


if __name__ == '__main__':
    main()
