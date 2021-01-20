# This defines:
#
#  LIBPHIDGETS_FOUND - system has libphidgets
#  LIBPHIDGETS_INCLUDE_DIR - the libphidgets include directory
#  LIBPHIDGETS_LIBRARIES - Link these to use libphidgets

if(APPLE)
    set(CMAKE_FIND_FRAMEWORK 1)
    find_path(LIBPHIDGETS_INCLUDE_DIR phidget22.h
      HINTS
        /Library/Frameworks
      )

    find_library(LIBPHIDGETS_LIBRARIES Phidget22)
elseif(UNIX)
    find_path(LIBPHIDGETS_INCLUDE_DIR phidget22.h
      HINTS
        ${PHIDGETS_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/libphidgets
      )

    find_library(LIBPHIDGETS_LIBRARIES NAMES libphidget22.a
      HINTS
      ${PHIDGETS_LIB_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/libphidgets/.libs)
else()
    find_path(LIBPHIDGETS_ROOT_DIR lib/c/phidget22.h
      HINTS
        ${PHIDGETS_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/libphidgets
        c:/phidget22-windevel
        lib/c
    )

    find_path(LIBPHIDGETS_INCLUDE_DIR phidget22.h
      HINTS
        ${PHIDGETS_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/libphidgets
        "${LIBPHIDGETS_ROOT_DIR}/lib/c"
        c:/phidget22-windevel
    )

    if(CMAKE_SIZEOF_VOID_P MATCHES 4)
      find_library(LIBPHIDGETS_LIBRARIES NAMES phidget22.lib phidget22
        HINTS
          c:/phidget22-windevel/x86          
          "${LIBPHIDGETS_ROOT_DIR}/lib/c/x86"
      )
    else()
      find_library(LIBPHIDGETS_LIBRARIES NAMES phidget22.lib phidget22
        HINTS
          c:/phidget22-windevel/x64
          "${LIBPHIDGETS_ROOT_DIR}/lib/c/x64"
      )
    endif()
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBPHIDGETS DEFAULT_MSG LIBPHIDGETS_LIBRARIES LIBPHIDGETS_INCLUDE_DIR)
mark_as_advanced(LIBPHIDGETS_INCLUDE_DIR LIBPHIDGETS_LIBRARIES)
