# pyipatcher
Incomplete iOS bootchain patchers in Python
## Notes
* Currently it's in a very incomplete stage with only kernel patcher
* It will be pushed to pip as a package later
* patchfinder64 is ported from [xerub's patchfinder](https://github.com/xerub/patchfinder64)
## Usage
* Kernel patcher:
```
Usage: kernelpatcher [input] [output] [args]
	-a		Patch AMFI
	-e		Patch root volume seal is broken (iOS 15 Only)
```
## Credits
Thanks to [plx](https://github.com/justtryingthingsout) for helping me with many fixes
