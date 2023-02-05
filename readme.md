# evecc
evecc is a tool for generating compiled.code files EVE online build 360229.

## getting started
Before starting, please make sure you have a copy of eveloader2 to run your code files.
1. generate new keys
```shell
evecc.exe --gen-key
```
2. extract the game's crypt key using `evecc.exe --dump-keys C:\path\to\Crucible\bin\blue.dll`.  This will generate `ccp.keys.crypt` and `ccp.keys.pub` files
3. inject a custom eveloader2 patch - create a new file in your eveloader2 folder called `patches.ini` and make a folder `patches`.
you will also want to copy your `evecc.keys.pub` and `ccp.keys.pub` into the `patches` folder.
```ini
[patches]
patch_list=public_key
[public_key]
name="Patch public key"
original_data=./patches/ccp.keys.pub
patched_data=./patches/evecc.keys.pub
```
4. please be aware that once you patch your public key in, the game will not recognize the original `compiled.code` file.  You will have to compile one and place that at `C:\ProgramData\eveloader2\script\`

## compiling code
please be aware that the order of the `-I` flags matters here.
```shell
set BP=C:\path\to\client\code
evecc.exe --compilecode -o compiled.code -I %BP%\carbon\client -I %BP%\carbon\common -I %BP%\eve\common -I %BP%\eve\client
```