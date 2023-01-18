import sys
from typing import BinaryIO

import click

from ..patchfinder64 import patchfinder64

# TODO: Docstrings


def patch_root_volume_seal(pf64: patchfinder64, verbose: bool) -> None:
    rh_auth_str = b"\"root volume seal is broken %p\\n\""
    rh_auth_str_loc = pf64.memmem(rh_auth_str)
    if rh_auth_str_loc == 0:
        click.secho(
            f"[ERROR] Could not find '{rh_auth_str_loc.decode()}' string. Exiting."
            if verbose
            else '[ERROR] Failed to patch kernel.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{rh_auth_str.decode()}' string at {hex(rh_auth_str_loc)}."
        )

    rh_auth_xref = pf64.xref(0, pf64.size, rh_auth_str_loc)
    if rh_auth_xref == 0:
        click.secho(
            f"[ERROR] Could not find '{rh_auth_str.decode()}' string reference. Exiting."
            if verbose
            else '[ERROR] Failed to patch kernel.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{rh_auth_str.decode()}' string reference at {hex(rh_auth_xref)}."
        )

    tbnz_ref = pf64.step_back(rh_auth_xref, 80, 0x36000000, 0x7E000000)
    if tbnz_ref == 0:
        click.secho(
            "[ERROR] Failed to find 'tbnz' instruction. Exiting."
            if verbose
            else '[ERROR] Failed to patch kernel.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(f"[DEBUG] Found 'tbnz' instruction at {hex(tbnz_ref)}.")

    click.echo(f'Patching root volume seal at {hex(tbnz_ref)}...')
    pf64.apply_patch(tbnz_ref, b"\x1f \x03\xd5")


def patch_rootfs_rw(pf64: patchfinder64, verbose: bool) -> None:
    rtfs_rw_str = b"%s:%d: %s Updating mount to read/write mode is not allowed"
    rtfs_rw_str_loc = pf64.memmem(rtfs_rw_str)
    if rtfs_rw_str_loc == 0:
        click.secho(
            f"[ERROR] Could not find '{rtfs_rw_str.decode()}' string. Exiting."
            if verbose
            else '[ERROR] Failed to patch kernel.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{rtfs_rw_str.decode()}' string at {hex(rtfs_rw_str_loc)}."
        )

    rtfs_rw_xref = pf64.xref(0, pf64.size, rtfs_rw_str_loc)
    if rtfs_rw_xref == 0:
        click.secho(
            f"[ERROR] Could not find '{rtfs_rw_str.decode()}' string reference. Exiting."
            if verbose
            else '[ERROR] Failed to patch kernel.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{rtfs_rw_str.decode()}' string reference at {hex(rtfs_rw_xref)}."
        )

    tbnz_xref = None
    for i in range(2):
        tbnz_xref = pf64.step_back(
            rtfs_rw_xref if i == 0 else tbnz_xref - 4, 800, 0x36000000, 0x7E000000
        )
        if tbnz_xref == 0:
            click.secho(
                "[ERROR] Failed to find 'tbnz' instruction. Exiting."
                if verbose
                else '[ERROR] Failed to patch kernel.',
                fg='red',
            )
            return

        elif verbose:
            click.echo(f"[DEBUG] Found 'tbnz' instruction at {hex(tbnz_xref)}.")

    click.echo(f'Patching root volume seal at {hex(tbnz_xref)}...')
    pf64.apply_patch(tbnz_xref, b"\x1f \x03\xd5")


def patch_amfi(pf64: patchfinder64, xnu_ver: int, verbose: bool) -> None:
    if xnu_ver >= 7938:  # 15.0b1
        amfi_str = b'Internal Error: No cdhash found.'
    else:
        amfi_str = b'entitlements too small'

    if verbose:
        click.echo(f"[DEBUG] Searching for '{amfi_str.decode()}' string...")

    amfi_str_loc = pf64.memmem(amfi_str)
    if amfi_str_loc == 0:
        click.secho(
            f"[ERROR] Could not find '{amfi_str.decode()}' string."
            if verbose
            else '[ERROR] Failed to patch kernel.',
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
            f"[ERROR] Could not find '{amfi_str.decode()}' string reference."
            if verbose
            else '[ERROR] Failed to patch kernel.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{amfi_str.decode()}' string xref at {hex(amfi_xref)}."
        )

    for i in range(2 if xnu_ver > 3789 else 3):  # 10.0b4
        next_bl = pf64.step(
            next_bl if i == 0 else next_bl + 0x4, 200, 0x94000000, 0xFC000000
        )
        if next_bl == 0:
            click.secho(
                '[ERROR] Could not find next bl.'
                if verbose
                else '[ERROR] Failed to patch kernel.',
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
            else '[ERROR] Failed to patch kernel.',
            fg='red',
        )
        return

    click.echo(f'Patching AppleMobileFileIntegrity at {hex(function)}...')
    pf64.apply_patch(function, b'\xe0\x03\x002\xc0\x03_\xd6', length=8)


@click.group()
def cli() -> None:
    pass


@cli.command(name='kernel')
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
@click.option(
    '-a',
    '--amfi',
    'patch_amfi',
    is_flag=True,
    help='Patch AppleMobileFileIntegrity.',
)
@click.option(
    '-e',
    '--rootvol-seal',
    'patch_rootvol_seal',
    is_flag=True,
    help='Patch root volume seal (iOS 15+ only).',
)
@click.option(
    '-u',
    '--update-rootfs-rw',
    'patch_update_rootfs_rw',
    is_flag=True,
    help='Patch rootfs r/w (iOS 15+ only).',
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def kernel(
    input: BinaryIO,
    output: BinaryIO,
    patch_amfi: bool,
    patch_rootvol_seal: bool,
    patch_update_rootfs_rw: bool,
    verbose: bool,
) -> None:
    if not verbose:
        sys.tracebacklimit = 0

    click.echo(f'Reading {input.name}...')
    data = input.read()

    if data[:4] == b'\xca\xfe\xba\xbe':
        click.echo('[NOTE] Detected fat macho kernel, removing header...')
        data = data[28:]

    pf64 = patchfinder64(data)
    xnu_ver = int(pf64.get_str(b'root:xnu-', 4, end=True))
    if verbose:
        click.echo(f'[DEBUG] Kernel version: {xnu_ver}')

    if patch_amfi:
        click.echo('Patching AppleMobileFileIntegrity...')
        patch_amfi(pf64, xnu_ver, verbose)

    if patch_rootvol_seal:
        if xnu_ver < 7938:  # 15.0b1
            click.secho(
                '[ERROR] root volume seal patch is only available for iOS 15+.',
                fg='red',
            )
            return

        patch_root_volume_seal(pf64)

    if patch_update_rootfs_rw:
        if xnu_ver < 7938:  # 15.0b1
            click.secho(
                '[ERROR] rootfs r/w patch is only available for iOS 15+.',
                fg='red',
            )
            return

        patch_rootfs_rw(pf64)

    click.echo(f'Writing patched kernel to {output.name}...')
    output.write(pf64.data)
