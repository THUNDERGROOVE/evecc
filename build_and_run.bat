REM this sample script expects that you have at least generated your keys and dumped CCP's
@echo off
SET PY_SRC=C:\Users\Nick\source\repos\crucible

SET EVECC_WD=C:\Users\Nick\source\repos\evecc\cmake-build-debug\
SET EVELOADER2_WD=C:\Users\Nick\source\repos\eveloader2\cmake-build-debug-vs2019\

pushd %EVECC_WD%
evecc.exe compilecode -o compiled.code -I %PY_SRC%\carbon\client -I %PY_SRC%\carbon\common -I %PY_SRC%\eve\common -I %PY_SRC%\eve\client -I %PY_SRC%\evedevtools -I %PY_SRC%\eve\alasiya
REM evecc.exe compilelib -i lib/evelib -o evelib.ccp
REM evecc.exe compilelib -i lib/carbonlib -o carbonlib.ccp
REM evecc.exe compilelib -i lib/carbonstdlib -o carbonstdlib.ccp
COPY compiled.code "C:\ProgramData\eveloader2\script"
REM COPY evelib.ccp "C:\ProgramData\eveloader2\lib"
REM COPY carbonlib.ccp "C:\ProgramData\eveloader2\lib"
REM COPY carbonstdlib.ccp "C:\ProgramData\eveloader2\lib"
popd

copy %EVECC_WD%\ccp.keys.pub %EVELOADER2_WD%\patches
copy %EVECC_WD%\evecc.keys.pub %EVELOADER2_WD%\patches
del C:\ProgramData\eveloader2\bin\blue.dll

pushd %EVELOADER2_WD%
eveloader2.exe -h eve.fag.haus -u groove -p password1
popd