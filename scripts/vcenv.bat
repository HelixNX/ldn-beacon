@echo off
rem Sets up the MSVC x64 environment and CC (clang-cl). Overrides: VCVARS (a vcvars64.bat), CC (a clang-cl.exe).
rem Otherwise Visual Studio is found with vswhere and clang-cl is its "C++ Clang tools" component, else MSYS2's.
if not defined VCVARS if defined NX_VCVARS set "VCVARS=%NX_VCVARS%"
if not defined CC if defined NX_CC set "CC=%NX_CC%"
if not defined VCVARS (
    for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined VCVARS (echo vcenv: no Visual Studio with the C++ x64 tools found; set VCVARS & exit /b 1)
if not exist "%VCVARS%" (echo vcenv: %VCVARS% does not exist & exit /b 1)
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VCVARS%" >nul || exit /b 1
if not defined CC if exist "%VCINSTALLDIR%Tools\Llvm\x64\bin\clang-cl.exe" set "CC=%VCINSTALLDIR%Tools\Llvm\x64\bin\clang-cl.exe"
if not defined CC if exist "%SystemDrive%\msys64\mingw64\bin\clang-cl.exe" set "CC=%SystemDrive%\msys64\mingw64\bin\clang-cl.exe"
if not defined CC (echo vcenv: no clang-cl found: install Visual Studio's "C++ Clang tools" or set CC & exit /b 1)
set "CC=%CC:\=/%"
exit /b 0
