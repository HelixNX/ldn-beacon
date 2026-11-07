@echo off
rem Windows build (the tools, and ldnbeacon with the ESP32-S3 radio): clang-cl + Ninja (scripts\vcenv.bat finds
rem Visual Studio), ENet, zstd and zlib from vcpkg (vcpkg install enet zstd zlib; VCPKG_ROOT). Linux: see CMakeLists.txt.
setlocal
set "ROOT=%~dp0"
rem before vcenv: Visual Studio's environment points VCPKG_ROOT at its own vcpkg
set "VCPKG_TREE="
for %%v in ("%VCPKG_ROOT%" "%VCPKG_INSTALLATION_ROOT%") do (
    if not defined VCPKG_TREE if exist "%%~v\installed\x64-windows\lib\enet.lib" set "VCPKG_TREE=%%~v\installed\x64-windows"
)
call "%ROOT%scripts\vcenv.bat" || exit /b 1
if not defined VCPKG_TREE if exist "%VCPKG_ROOT%\installed\x64-windows\lib\enet.lib" set "VCPKG_TREE=%VCPKG_ROOT%\installed\x64-windows"
if not exist "%ROOT%build\build.ninja" (
    if not defined VCPKG_TREE (echo ldn-beacon: no ENet in vcpkg: vcpkg install enet zstd zlib, then set VCPKG_ROOT & exit /b 1)
    cmake -G Ninja -S "%ROOT%." -B "%ROOT%build" -DCMAKE_C_COMPILER="%CC%" -DVCPKG_INSTALLED="%VCPKG_TREE%" %* || exit /b 1
)
cmake --build "%ROOT%build"
