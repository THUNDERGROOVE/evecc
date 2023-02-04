# evecc
evecc is a tool for generating compiled.code files EVE online build 360229.

## getting started
Before starting, please make sure you have a copy of eveloader2 to run your code files.
1. generate new keys
```shell
evecc.exe --gen-key
```
2. find the game's original public key.  this can be found by searching `blue.dll` for the following bytes `06 02 00 00 00 24 00 00 52 53 41 31`.  the key starts at the first `06` and is 148 bytes long. You can quite easily extract this with a hex editor of your choice.
3. inject a custom eveloader2 patch - create a new file in your eveloader2 folder called `patches.ini` and make a folder `patches`.
you will also want to copy your `evecc.keys.pub` and `original_pub_key` into the `patches` folder.
```ini
[patches]
patch_list=public_key
[public_key]
name="Patch public key"
original_data=./patches/original_pub_key
patched_data=./patches/evecc.keys.pub
```
4. please be aware that once you patch your public key in, the game will not recognize the original `compiled.code` file.  You will have to compile one and place that at `C:\ProgramData\eveloader2\script\`

## compiling code
please be aware that the order of the `-I` flags matters here.
```shell
set BP=C:\path\to\client\code
evecc.exe --compilecode -o compiled.code -I %BP%\carbon\client -I %BP%\carbon\common -I %BP%\eve\common -I %BP%\eve\client
```