import click
from .cli.kernelpatcher import kernelpatcher

@click.group()
def cli():
    pass
   
cli.add_command(kernelpatcher)
cli.context_settings = dict(help_option_names=['-h', '--help'])

cli()