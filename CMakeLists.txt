# ldn-beacon: a real Switch's local play (LDN over Wi-Fi) bridged into an Eden-compatible multiplayer room.
#   Linux (the beacon, CachyOS):  sudo pacman -Sy --needed base-devel cmake enet zstd iw
#                                 cmake -B build && cmake --build build
#   Windows (no ldnbeacon):       vcpkg install enet zstd; cmake -G Ninja -B build -DCMAKE_C_COMPILER=clang-cl
#                                 (VCPKG_ROOT, or -DVCPKG_INSTALLED=<vcpkg>/installed/x64-windows)
cmake_minimum_required(VERSION 3.20)
project(ldn_beacon C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

if(WIN32)
    if(NOT VCPKG_INSTALLED AND DEFINED ENV{VCPKG_ROOT})
        file(TO_CMAKE_PATH "$ENV{VCPKG_ROOT}/installed/x64-windows" VCPKG_INSTALLED)
    endif()
    set(VCPKG_INSTALLED "${VCPKG_INSTALLED}" CACHE PATH "vcpkg's installed/x64-windows (ENet, zstd)")
    find_path(ENET_INCLUDE enet/enet.h HINTS "${VCPKG_INSTALLED}/include" REQUIRED)
    find_library(ENET_LIB enet HINTS "${VCPKG_INSTALLED}/lib" REQUIRED)
    find_path(ZSTD_INCLUDE zstd.h HINTS "${VCPKG_INSTALLED}/include" REQUIRED)
    find_library(ZSTD_LIB zstd HINTS "${VCPKG_INSTALLED}/lib" REQUIRED)
    set(PLATFORM_LIBS ws2_32 winmm)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    find_path(ENET_INCLUDE enet/enet.h REQUIRED)
    find_library(ENET_LIB enet REQUIRED)
    find_path(ZSTD_INCLUDE zstd.h REQUIRED)
    find_library(ZSTD_LIB zstd REQUIRED)
    set(PLATFORM_LIBS)
    add_compile_options(-Wall -Wextra)
endif()

# LDN itself (crypto, keys, the advertisement), no network libraries: builds anywhere
add_library(ldncore STATIC src/common.c src/crypto.c src/ldnkeys.c src/adv.c src/frames.c src/ccmp.c src/ldnauth.c src/bridge.c)
target_include_directories(ldncore PUBLIC src)

add_executable(advdump src/advdump.c)
target_link_libraries(advdump PRIVATE ldncore)
add_executable(frametest src/frametest.c)
target_link_libraries(frametest PRIVATE ldncore)
add_executable(ccmptest src/ccmptest.c)
target_link_libraries(ccmptest PRIVATE ldncore)
add_executable(authtest src/authtest.c)
target_link_libraries(authtest PRIVATE ldncore)
add_executable(bridgetest src/bridgetest.c)
target_link_libraries(bridgetest PRIVATE ldncore)

add_library(room STATIC src/room.c)
target_link_libraries(room PUBLIC ldncore)
target_include_directories(room PUBLIC src "${ENET_INCLUDE}" "${ZSTD_INCLUDE}")
target_link_libraries(room PUBLIC "${ENET_LIB}" "${ZSTD_LIB}" ${PLATFORM_LIBS})

add_executable(roomtest src/roomtest.c)
target_link_libraries(roomtest PRIVATE room)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # the beacon itself: a monitor interface and raw 802.11 frames (radio.c)
    add_executable(ldnbeacon src/ldnbeacon.c src/radio.c src/ap.c)
    target_link_libraries(ldnbeacon PRIVATE room)
endif()

if(WIN32)
    # vcpkg's DLLs next to the exe
    foreach(_dll enet zstd)
        if(EXISTS "${VCPKG_INSTALLED}/bin/${_dll}.dll")
            add_custom_command(TARGET roomtest POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different
                               "${VCPKG_INSTALLED}/bin/${_dll}.dll" "$<TARGET_FILE_DIR:roomtest>")
        endif()
    endforeach()
endif()
