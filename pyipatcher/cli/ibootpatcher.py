import click
from pyipatcher.patchfinder.ibootpatchfinder import ibootpatchfinder
from pyipatcher.logger import get_my_logger

@click.command()
@click.argument('input', type=click.File('rb'))
@click.argument('output', type=click.File('wb'))
@click.option(
    '-b',
    '--boot-args',
    metavar='"BOOTARGS"',
    nargs=1,
    help='Apply custom boot-args'
)
@click.option(
    '-n',
    '--unlock-nvram',
    is_flag=True,
    help='Apply unlock nvram patch'
)
@click.option(
    '-c',
    '--cmd-handler',
    metavar='COMMAND POINTER',
    nargs=2,
    required=False,
    help='Relocate command handler\'s pointer'
)
@click.option(
    '-r',
    '--reboot-to-fsboot',
    is_flag=True,
    help='Apply change reboot to fsboot patch'
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Show more debug information'
)

def ibootpatcher(input, output, unlock_nvram, cmd_handler, reboot_to_fsboot, boot_args, verbose):
    logger = get_my_logger(verbose)
    ibpf = ibootpatchfinder(input.read(), verbose)
    if ibpf.has_kernel_load:
        if boot_args:
            logger.info(f'Getting get_bootarg_patch({boot_args})')
            if ibpf.get_bootarg_patch(boot_args) == -1:
                logger.warning(f'Failed getting get_bootarg_patch({boot_args})')
        logger.info('Getting get_debug_enabled_patch()')
        if ibpf.get_debug_enabled_patch() == -1:
            logger.warning('Failed getting get_debug_enabled_patch()')
    if ibpf.has_recovery_console:
        if cmd_handler:
            logger.info(f'Getting get_cmd_handler_patch({cmd_handler[0]}, {cmd_handler[1]})')
            ptr = int(cmd_handler[1], 0)
            if ibpf.get_cmd_handler_patch(cmd_handler[0], ptr) == -1:
                logger.warning(f'Failed getting get_cmd_handler_patch({cmd_handler[0]}, {cmd_handler[1]})')
        if unlock_nvram:
            logger.info('Getting get_unlock_nvram_patch()')
            if ibpf.get_unlock_nvram_patch() == -1:
                logger.warning('Failed getting get_unlock_nvram_patch()')
            logger.info('Getting get_freshnonce_patch()')
            if ibpf.get_freshnonce_patch() == -1:
                logger.warning('Failed getting get_freshnonce_patch()')
        if reboot_to_fsboot:
            logger.info('Getting get_change_reboot_to_fsboot_patch()')
            if ibpf.get_change_reboot_to_fsboot_patch() == -1:
                logger.warning('Failed getting get_change_reboot_to_fsboot_patch()')
    logger.info('Getting get_sigcheck_patch()')
    if ibpf.get_sigcheck_patch() == -1:
        logger.warning('Failed getting get_sigcheck_patch()')
    logger.info(f'Writing out patched file to {output.name}')
    output.write(ibpf.output)
    return 0

