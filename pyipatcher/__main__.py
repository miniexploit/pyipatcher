import click
from .cli.ramdiskpatcher import ramdiskpatcher
from .cli.kernelpatcher import kernelpatcher
from .cli.ibootpatcher import ibootpatcher

@click.group()
def cli():
    pass
   
cli.add_command(ramdiskpatcher)
cli.add_command(kernelpatcher)
cli.add_command(ibootpatcher)


cli.context_settings = dict(help_option_names=['-h', '--help'])