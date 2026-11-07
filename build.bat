@echo off
rem Windows build (roomtest only; the beacon itself is Linux): clang-cl + Ninja from nxrecomp\tools\vcenv.bat,
rem ENet and zstd from vcpkg (VCPKG_ROOT, or pass -DVCPKG_INSTALLED=... on the first run).
set ROOT=%~dp0
call "%ROOT%..\nxrecomp\tools\vcenv.bat" || exit /b 1
if not exist "%ROOT%build\build.ninja" (
    cmake -G Ninja -S "%ROOT%." -B "%ROOT%build" -DCMAKE_C_COMPILER="%NX_CC%" %* || exit /b 1
)
cmake --build "%ROOT%build"
