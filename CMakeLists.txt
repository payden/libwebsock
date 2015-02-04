cmake_minimum_required(VERSION 2.6) 
project(libwebsock)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

find_package(OpenSSL)

if (OPENSSL_FOUND)
    set(WEBSOCK_HAVE_SSL 1)
endif()

find_package(Libevent REQUIRED)
list(APPEND WEBSOCK_DEPS ${LIBEVENT_LIBRARIES})

find_package(Threads)
list(APPEND WEBSOCK_DEPS ${CMAKE_THREAD_LIBS_INIT})

if (LINUX)
    list(APPEND WEBSOCK_DEPS rt)
endif()

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
    src/sha1.h)

set(HDR_LIB_PUBLIC
    src/websock.h
    src/types.h
    src/api.h
    src/default_callbacks.h
    src/frames.h
    src/utf.h
    src/util.h)

if (WEBSOCK_HAVE_SSL)
    list(APPEND SRC_LIB src/openssl.c)
endif()

source_group("Headers Lib Private"  FILES ${HDR_LIB_PRIVATE})
source_group("Headers Lib Public"   FILES ${HDR_LIB_PUBLIC})
source_group("Source Lib"           FILES ${SRC_LIB})

foreach (HDR ${HDR_LIB_PUBLIC})
    get_filename_component(HDR_NAME ${HDR} NAME)
    message("${PROJECT_SOURCE_DIR}/${HDR} -> ${PROJECT_BINARY_DIR}/include/websock/${HDR_NAME}")
    configure_file("${PROJECT_SOURCE_DIR}/${HDR}" "${PROJECT_BINARY_DIR}/include/websock/${HDR_NAME}" COPYONLY)
endforeach()

configure_file("${PROJECT_SOURCE_DIR}/websock_config.h.cmake" "${PROJECT_BINARY_DIR}/include/websock/websock_config.h")

include_directories(
    "${PROJECT_SOURCE_DIR}"
    "${PROJECT_BINARY_DIR}/include"
    "${LIBEVENT_INCLUDE_DIR}")

add_library(websock ${SRC_LIB} ${HDR_LIB_PRIVATE} ${HDR_LIB_PUBLIC})

target_link_libraries(websock ${WEBSOCK_DEPS})

#
# Examples
#
add_executable(autobahn-echo examples/autobahn-echo.c)
target_link_libraries(autobahn-echo websock ${WEBSOCK_DEPS})

