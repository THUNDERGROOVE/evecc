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

## building evecc
1. install Visual Studio Installer
2. in the Visual Studio Installer, install the following
   1. `.NET framework 4.7.2 SDK`
   2. `.NET framework 4.7.2 targeting pack`
   3. `CMake tools for Winddows`
   4. `MSVC v142 - VS 2019 c++ x64/x86 build tools (Latest)`
   5. `Windows Universal CRT SDK`
   6. `C++ ATL for latest v142 bubild tools (x86 & x64)`
   7. `C++ MFC for latest v142 bubild tools (x86 & x64)`
   8. `Windows 10 SDK (<any version>)`
   9. `Windows Universal C Runtime`
2. install Ninja
3. run the following script in `x64 Native Tools Command Prompt for VS 2019`

```shell
set VCPKG_DEFAULT_TRIPLET=x64-windows
mkdir build
cd build
cmake -G "Ninja" ..
ninja
```
