import click

from pyipatcher import __version__

from .cli.asr import cli as asr
from .cli.kernel import cli as kernel

cli = click.CommandCollection(sources=[asr, kernel])
cli.context_settings = {'help_option_names': ['-h', '--help']}
