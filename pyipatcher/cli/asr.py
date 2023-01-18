import sys
from typing import BinaryIO

import click

from ..patchfinder64 import arm64_branch_instruction, patchfinder64

# TODO: Docstrings


def patch_asr_sigchecks(pf64: patchfinder64, verbose: bool) -> None:
    failed_str = b'Image failed signature verification'
    failed_str_loc = pf64.memmem(failed_str)
    if failed_str_loc == 0:
        click.secho(
            f"[ERROR] Could not find '{failed_str.decode()}' string. Exiting."
            if verbose
            else '[ERROR] Failed to patch ASR.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{failed_str.decode()}' string at {hex(failed_str_loc)}."
        )

    passed_str = b"Image passed signature verification"
    passed_str_loc = pf64.memmem(passed_str)
    if passed_str_loc == 0:
        click.secho(
            f"[ERROR] Could not find '{passed_str.decode()}' string. Exiting."
            if verbose
            else '[ERROR] Failed to patch ASR.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{passed_str.decode()}' string at {hex(failed_str_loc)}."
        )

    failed_xref = pf64.xref(0, len(pf64), failed_str_loc)
    if failed_xref == 0:
        click.secho(
            f"[ERROR] Could not find '{failed_str.decode()}' string reference. Exiting."
            if verbose
            else '[ERROR] Failed to patch ASR.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{failed_str.decode()}' string reference at {hex(failed_xref)}."
        )

    passed_xref = pf64.xref(0, len(pf64), passed_str_loc)
    if passed_xref == 0:
        click.secho(
            f"[ERROR] Could not find '{passed_str.decode()}' string reference. Exiting."
            if verbose
            else '[ERROR] Failed to patch ASR.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(
            f"[DEBUG] Found '{passed_str.decode()}' string reference at {hex(passed_xref)}."
        )

    our_branch = arm64_branch_instruction(failed_xref, passed_xref)
    if our_branch == 0:
        click.secho(
            '[ERROR] Failed to create branch instruction. Exiting.'
            if verbose
            else '[ERROR] Failed to patch ASR.',
            fg='red',
        )
        return

    elif verbose:
        click.echo(f"[DEBUG] Created branch instruction at {hex(our_branch)}.")

    click.echo('Patching failed signature check...')
    pf64.apply_patch(passed_xref, our_branch.to_bytes(4, byteorder='little'))


@click.group()
def cli() -> None:
    pass


@cli.command()
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def asr(
    input: BinaryIO,
    output: BinaryIO,
    verbose: bool,
) -> None:
    if not verbose:
        sys.tracebacklimit = 0

    click.echo(f'Reading {input.name}...')
    data = input.read()

    click.echo('Patching signature checks...')
    pf64 = patchfinder64(data)
    patch_asr_sigchecks(pf64, verbose)

    click.echo(f'Writing patched ASR to {output.name}...')
    output.write(pf64.data)
