# - Find LibEvent (a cross event library)
# This module defines
# LIBEVENT_INCLUDE_DIR, where to find LibEvent headers
# LIBEVENT_LIBRARIES, Libevent libraries
# LibEvent_FOUND, If false, do not try to use libevent

set(LibEvent_EXTRA_PREFIXES /usr/local /opt/local "$ENV{HOME}" /usr/lib)
foreach(prefix ${LibEvent_EXTRA_PREFIXES})
	list(APPEND LibEvent_INCLUDE_PATHS "${prefix}/include" "${prefix}/")
	list(APPEND LIBEVENT_LIB_DIR_PATHS "${prefix}/lib")
endforeach()

find_path(LIBEVENT_INCLUDE_DIRS event2/event.h)
find_library(LIBEVENT_LIB NAMES libevent.a)
find_library(LIBEVENT_PTHREADS_LIB NAMES libevent_pthreads.a)
find_library(LIBEVENT_CORE_LIB NAMES libevent_core.a)
find_library(LIBEVENT_EXTRA_LIB NAMES libevent_extra.a)

set(LIBEVENT_LIBRARIES
    ${LIBEVENT_LIB}
    ${LIBEVENT_PTHREADS_LIB}
    ${LIBEVENT_CORE_LIB}
    ${LIBEVENT_EXTRA_LIB})


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibEvent DEFAULT_MSG
                                  LIBEVENT_LIBRARIES
                                  LIBEVENT_INCLUDE_DIRS)

mark_as_advanced(
    LIBEVENT_LIBRARIES
    LIBEVENT_INCLUDE_DIRS
  )
