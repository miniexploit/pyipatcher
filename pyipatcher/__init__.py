from importlib.metadata import version
import pyipatcher.patchfinder

__version__ = version(__package__)
print(f'pyipatcher version: {__version__}')