from importlib.metadata import version
import pyipatcher.patchfinder
import pyipatcher.logger
import pyipatcher.ipatcher

__version__ = version(__package__)
print(f'pyipatcher version: {__version__}')