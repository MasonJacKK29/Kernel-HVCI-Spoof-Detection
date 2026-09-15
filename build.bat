@echo off
setlocal
cd /d "%~dp0"

echo ===============================================================
echo  Core Isolation Spoof Detector - Build
echo ===============================================================
echo.

rem Locate vswhere.exe with hardcoded paths. Expanding %ProgramFiles(x86)%
rem inside SET/IF blocks trips the CMD parser on the parentheses in
rem "Program Files (x86)", so we avoid that expansion entirely.
set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :nofound

set "VSPATH="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH goto :novs

echo [INFO] Visual Studio: %VSPATH%
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 goto :vcvarsfail

echo [INFO] Compiling main.cpp -^> coreiso_check.exe ...
echo.
cl /nologo /std:c++17 /O2 /EHsc /W3 /MT /Fe:coreiso_check.exe main.cpp /link advapi32.lib wbemuuid.lib ole32.lib oleaut32.lib
if errorlevel 1 goto :buildfail

del main.obj >nul 2>&1

echo.
echo ===============================================================
echo  BUILD OK: coreiso_check.exe
echo ===============================================================
echo.
echo  Usage (run as Administrator):
echo      coreiso_check.exe
echo.
echo  Exit codes:
echo      0 = CLEAN
echo      1 = WARNING  (HVCI disabled or unverifiable)
echo      2 = SEVERE   (spoof / HVCI unlock trace)
echo.
pause
exit /b 0

:nofound
echo [ERROR] vswhere.exe not found. Install Visual Studio 2019+ with the
echo         "Desktop development with C++" workload.
pause
exit /b 1

:novs
echo [ERROR] Visual Studio with C++ x64 tools not found by vswhere.
pause
exit /b 1

:vcvarsfail
echo [ERROR] vcvars64.bat setup failed.
pause
exit /b 1

:buildfail
echo.
echo [FAIL] Compilation failed - see errors above.
pause
exit /b 1
