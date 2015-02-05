cmake_minimum_required(VERSION 2.6) 
project(libwebsock)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")

set(LIBEVENT_DIR "" CACHE PATH "Location of Libevent build try if you have built it yourself. If this is no set, the system version will be used")

if (WIN32)
    set(PTHREADS_WIN32_DIR "" CACHE PATH "Location for pthreads-win32 pre-built libraries root 'c:/path/to/pthreads-w32-2-9-1-release/Pre-built.2'. Get ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.zip or latest release")
endif()

if (MSVC)
    # Turn off stupid microsoft security warnings.
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
endif(MSVC)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

if (APPLE)
    # Get rid of deprecated warnings for OpenSSL on OSX 10.7 and greater.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=deprecated-declarations -Wno-deprecated-declarations")
    # Get rid of "clang: warning: argument unused during compilation: -I etc
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Qunused-arguments")
    endif()
endif()

#
# Find libs
#

if (WIN32)
    list(APPEND WEBSOCK_DEPS ws2_32.lib)
endif()

# OpenSSL
find_package(OpenSSL)

if (OPENSSL_FOUND)
    set(WEBSOCK_HAVE_SSL 1)
    include_directories("${OPENSSL_INCLUDE_DIR}")
endif()

# Libevent
if (LIBEVENT_DIR)
    find_package(Libevent REQUIRED CONFIG NO_DEFAULT_PATH NO_CMAKE_PACKAGE_REGISTRY
                PATHS ${LIBEVENT_DIR})
else()
    find_package(Libevent REQUIRED)
endif()

list(APPEND WEBSOCK_DEPS ${LIBEVENT_LIBRARIES})
include_directories("${LIBEVENT_INCLUDE_DIRS}")

# Pthreads
if (WIN32)
    if (NOT PTHREADS_WIN32_DIR)
        message(FATAL_ERROR "You need to specify -DPTHREADS_WIN32_DIR")
    endif()

    set(Threads_INCLUDE_DIR "${PTHREADS_WIN32_DIR}/include")
    set(CMAKE_THREAD_LIBS_INIT
        User32.lib 
        Shell32.lib 
        iphlpapi.lib
        "${PTHREADS_WIN32_DIR}/lib/x86/pthreadVC2.lib")
    set(PTHREAD_WIN32_DLL_PATH "${PTHREADS_WIN32_DIR}/dll/x86/pthreadVC2.dll")
else()
    find_package(Threads)
endif()

include_directories(${Threads_INCLUDE_DIR})
list(APPEND WEBSOCK_DEPS ${CMAKE_THREAD_LIBS_INIT})

# Require for clock_get_time
if (LINUX)
    list(APPEND WEBSOCK_DEPS rt)
endif()

#
# Sources
#

set(SRC_LIB
    src/api.c
    src/base64.c
    src/default_callbacks.c
    src/frames.c
    src/sha1.c
    src/utf.c
    src/util.c
    src/websock.c)

set(HDR_LIB_PRIVATE
    src/sha1.h
    src/utf.h)

set(HDR_LIB_PUBLIC
    src/websock.h
    src/types.h
    src/api.h
    src/default_callbacks.h
    src/frames.h    
    src/util.h)

if (WEBSOCK_HAVE_SSL)
    list(APPEND SRC_LIB src/openssl.c)
endif()

source_group("Headers Lib Private"  FILES ${HDR_LIB_PRIVATE})
source_group("Headers Lib Public"   FILES ${HDR_LIB_PUBLIC})
source_group("Source Lib"           FILES ${SRC_LIB})

foreach (HDR ${HDR_LIB_PUBLIC})
    get_filename_component(HDR_NAME ${HDR} NAME)
    #message("${PROJECT_SOURCE_DIR}/${HDR} -> ${PROJECT_BINARY_DIR}/include/websock/${HDR_NAME}")
    configure_file("${PROJECT_SOURCE_DIR}/${HDR}" "${PROJECT_BINARY_DIR}/include/websock/${HDR_NAME}" COPYONLY)
endforeach()

configure_file("${PROJECT_SOURCE_DIR}/websock_config.h.cmake" "${PROJECT_BINARY_DIR}/include/websock/websock_config.h")

include_directories(
    "${PROJECT_SOURCE_DIR}"
    "${PROJECT_BINARY_DIR}/include")

add_library(websock ${SRC_LIB} ${HDR_LIB_PRIVATE} ${HDR_LIB_PUBLIC})

target_link_libraries(websock ${WEBSOCK_DEPS})

#
# Examples
#
add_executable(autobahn-echo examples/autobahn-echo.c)
target_link_libraries(autobahn-echo websock)

if (WIN32)
    add_custom_command(
        TARGET autobahn-echo 
        POST_BUILD 
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${PTHREAD_WIN32_DLL_PATH} $<TARGET_FILE_DIR:autobahn-echo> VERBATIM)
endif()
