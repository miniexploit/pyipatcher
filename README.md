# pyipatcher
Incomplete iOS bootchain patchers in Python
## Notes
* ~~It will be pushed to pip as a package later~~
* You can now install it locally (see Installation)
* patchfinder64 is ported from [xerub's patchfinder](https://github.com/xerub/patchfinder64)
* kernelpatcher is ported from [palera1n team's fork of Kernel64Patcher](https://github.com/palera1n/Kernel64Patcher)
## Installation
* Install from PyPI (bug-free):
```
python3 -m pip install pyipatcher
```
* Install locally (receive updates more often):
```
git clone https://github.com/Mini-Exploit/pyipatcher
cd pyipatcher
./install.sh
```
## Usage
```
$ pyipatcher
pyipatcher version: 1.1.1
Usage: pyipatcher [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  ibootpatcher
  kernelpatcher
  ramdiskpatcher

```
## Future plan
* Complete kernel patcher ✅ 
* Add iBoot patcher, ASR patcher, restored_external patcher  ✅ 
## Credits
Thanks to [plx](https://github.com/justtryingthingsout) for helping me with many fixes
