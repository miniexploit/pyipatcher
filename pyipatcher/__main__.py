import click
from .cli.kernelpatcher import kernelpatcher
from .cli.asrpatcher import asrpatcher
import logging, coloredlogs
from .logger import get_my_logger

@click.group()
def cli():
    pass
   
cli.add_command(kernelpatcher)
cli.add_command(asrpatcher)

cli.context_settings = dict(help_option_names=['-h', '--help'])

logger = get_my_logger('main')

def main():
    try:
        cli()
    except Exception as e:
        logger.error(f'pyipatcher failed with reason: {e}')