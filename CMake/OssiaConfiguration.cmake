# Build settings :
option(OSSIA_SANITIZE "Sanitize build" OFF)
option(OSSIA_TIDY "Use clang-tidy" OFF)
option(OSSIA_STATIC "Make a static build" OFF)
option(OSSIA_COVERAGE "Run code coverage" OFF)
option(OSSIA_EXAMPLES "Build examples" OFF)
option(OSSIA_TESTING "Build tests" OFF)
option(OSSIA_CI "Continuous integration run" OFF)
option(OSSIA_FRAMEWORK "Build an OS X framework" OFF)
option(OSSIA_DISABLE_COTIRE "Disable cotire" OFF)
option(OSSIA_NO_SONAME "Set NO_SONAME property" ON)
option(OSSIA_LTO "Link-time optimizations. Fails on Windows." OFF)
option(OSSIA_OSX_FAT_LIBRARIES "Build 32 and 64 bit fat libraries on OS X" OFF)
option(OSSIA_OSX_RETROCOMPATIBILITY "Build for older OS X versions" OFF)
option(OSSIA_USE_FAST_LINKER "Use a faster linker (GNU gold or LLVM lld). Fails on some Ubuntu systems" OFF)
option(OSSIA_MOST_STATIC "Try to make binaries that are mostly static" OFF)
option(OSSIA_DATAFLOW "Dataflow features" ON)
option(OSSIA_EDITOR "Editor features" ON)
option(OSSIA_GFX "Graphics features" ON)
option(OSSIA_SPLIT_DEBUG "Split debug info" ON)
option(OSSIA_NO_DEBUG_INFO "No debug info" OFF)
option(OSSIA_HIDE_ALL_SYMBOLS "Hide all symbols from the ossia lib" OFF)
#option(OSSIA_SUBMODULE_AUTOUPDATE "Auto update submodule" ON)
set(OSSIA_SUBMODULE_AUTOUPDATE ON CACHE BOOL "Auto update submodule")

# Bindings :
option(OSSIA_JAVA "Build JNI bindings" OFF)
option(OSSIA_PD "Build PureData externals" OFF)
option(OSSIA_PD_ONLY "Build and install only PureData externals" OFF)
option(OSSIA_MAX "Build Max/MSP externals" OFF)
option(OSSIA_MAX_ONLY "Build and install only Max/MSP externals" OFF)
option(OSSIA_PYTHON "Build Python bindings" OFF)
option(OSSIA_PYTHON_ONLY "Build and install only Python bindings" OFF)
option(OSSIA_QT "Build Qt bindings. Implies websocket, serial, http." OFF)
option(OSSIA_C "Build C bindings" OFF)
option(OSSIA_CPP "Build CPP bindings" OFF)
option(OSSIA_CPP_ONLY "Build only ossia-cpp and install only needed header" OFF)
option(OSSIA_UNITY3D "Build Unity3D bindings" OFF)
option(OSSIA_QML "Build QML bindings" OFF)
option(OSSIA_QML_ONLY "Build and install only QML bindings" OFF)
option(OSSIA_QML_SCORE "Build QML bindings to scoring parts" OFF)
option(OSSIA_NODEJS "Build Node.js bindings" OFF)
# Protocols :
option(OSSIA_PROTOCOL_AUDIO "Enable Audio protocol" ON)
option(OSSIA_PROTOCOL_MIDI "Enable MIDI protocol" ON)
option(OSSIA_PROTOCOL_OSC "Enable OSC protocol" ON)
option(OSSIA_PROTOCOL_MINUIT "Enable Minuit protocol" ON)
option(OSSIA_PROTOCOL_OSCQUERY "Enable OSCQuery protocol" ON)
option(OSSIA_PROTOCOL_HTTP "Enable HTTP protocol" ON) # Requires Qt
option(OSSIA_PROTOCOL_WEBSOCKETS "Enable WebSockets protocol" OFF) # Requires Qt
option(OSSIA_PROTOCOL_SERIAL "Enable Serial port protocol" OFF) # Requires Qt
option(OSSIA_PROTOCOL_PHIDGETS "Enable Phidgets protocol" OFF) # Requires Phidgets library
option(OSSIA_PROTOCOL_LEAPMOTION "Enable Leapmotion protocol" OFF) # Requires LeapMotion Orion library
option(OSSIA_PROTOCOL_JOYSTICK "Enable Joystick protocol" ON)  # Requires SDL2 library
option(OSSIA_PROTOCOL_WIIMOTE "Enable Wiimote Protocol" ON) #use wiiuse
option(OSSIA_PROTOCOL_ARTNET "Enable artnet protocol" ON) #use libartnet
option(OSSIA_DISABLE_QT_PLUGIN "Disable building of a Qt plugin" OFF)
option(OSSIA_DNSSD "Enable DNSSD support" ON)
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${PROJECT_SOURCE_DIR}/CMake;${PROJECT_SOURCE_DIR}/CMake/cmake-modules;")

if(NOT OSSIA_SDK)
  set(OSSIA_SDK ${OSSIA_3RDPARTY_FOLDER}/win_audio_sdk)
endif()

set(CMAKE_PREFIX_PATH
  "${OSSIA_SDK}/SDL2/cmake"
  "${OSSIA_SDK}/portaudio/lib/cmake"
  "${CMAKE_PREFIX_PATH}"
)

if(OSSIA_CPP_ONLY)
  set(OSSIA_DATAFLOW 0)
  set(OSSIA_EDITOR 0)
  set(OSSIA_JAVA 0)
  set(OSSIA_PD 0)
  set(OSSIA_MAX 0)
  set(OSSIA_PYTHON 0)
  set(OSSIA_QT 0)
  set(OSSIA_C 0)
  set(OSSIA_CPP 1)
  set(OSSIA_UNITY3D 0)
  set(OSSIA_QML 0)
  set(OSSIA_QML_SCORE 0)
  set(OSSIA_PROTOCOL_AUDIO 0)
  set(OSSIA_PROTOCOL_MIDI 0)
  set(OSSIA_PROTOCOL_OSC 0)
  set(OSSIA_PROTOCOL_MINUIT 0)
  set(OSSIA_PROTOCOL_OSCQUERY 1)
  set(OSSIA_PROTOCOL_HTTP 0)
  set(OSSIA_PROTOCOL_WEBSOCKETS 0)
  set(OSSIA_PROTOCOL_SERIAL 0)
  set(OSSIA_PROTOCOL_PHIDGETS 0)
  set(OSSIA_PROTOCOL_LEAPMOTION 0)
  set(OSSIA_PROTOCOL_JOYSTICK 0)
  set(OSSIA_PROTOCOL_WIIMOTE 0)
  set(OSSIA_DISABLE_QT_PLUGIN 0)
  set(OSSIA_DNSSD 1)
endif()

if(OSSIA_PD_ONLY)
  set(OSSIA_NO_INSTALL 1)
  set(OSSIA_STATIC 1)
  set(OSSIA_DATAFLOW 0)
  set(OSSIA_EDITOR 0)
  set(OSSIA_JAVA 0)
  set(OSSIA_PD 1)
  set(OSSIA_PYTHON 0)
  set(OSSIA_QT 0)
  set(OSSIA_C 0)
  set(OSSIA_CPP 0)
  set(OSSIA_UNITY3D 0)
  set(OSSIA_QML 0)
  set(OSSIA_QML_SCORE 0)
  set(OSSIA_PROTOCOL_AUDIO 0)
  set(OSSIA_PROTOCOL_MIDI 0)
  set(OSSIA_PROTOCOL_OSC 1)
  set(OSSIA_PROTOCOL_MINUIT 1)
  set(OSSIA_PROTOCOL_OSCQUERY 1)
  set(OSSIA_PROTOCOL_HTTP 0)
  set(OSSIA_PROTOCOL_WEBSOCKETS 0)
  set(OSSIA_PROTOCOL_SERIAL 0)
  set(OSSIA_PROTOCOL_PHIDGETS 0)
  set(OSSIA_PROTOCOL_LEAPMOTION 0)
  set(OSSIA_PROTOCOL_JOYSTICK 0)
  set(OSSIA_PROTOCOL_WIIMOTE 0)
  set(OSSIA_DISABLE_QT_PLUGIN 0)
  set(OSSIA_DNSSD 1)
endif()

if(OSSIA_MAX_ONLY)
  set(OSSIA_NO_INSTALL 1)
  set(OSSIA_STATIC 1)
  set(OSSIA_DATAFLOW 0)
  set(OSSIA_EDITOR 0)
  set(OSSIA_JAVA 0)
  set(OSSIA_MAX 1)
  set(OSSIA_PYTHON 0)
  set(OSSIA_QT 0)
  set(OSSIA_C 0)
  set(OSSIA_CPP 0)
  set(OSSIA_UNITY3D 0)
  set(OSSIA_QML 0)
  set(OSSIA_QML_SCORE 0)
  set(OSSIA_PROTOCOL_AUDIO 0)
  set(OSSIA_PROTOCOL_MIDI 0)
  set(OSSIA_PROTOCOL_OSC 1)
  set(OSSIA_PROTOCOL_MINUIT 1)
  set(OSSIA_PROTOCOL_OSCQUERY 1)
  set(OSSIA_PROTOCOL_HTTP 0)
  set(OSSIA_PROTOCOL_WEBSOCKETS 0)
  set(OSSIA_PROTOCOL_SERIAL 0)
  set(OSSIA_PROTOCOL_PHIDGETS 0)
  set(OSSIA_PROTOCOL_LEAPMOTION 0)
  set(OSSIA_PROTOCOL_JOYSTICK 0)
  set(OSSIA_PROTOCOL_WIIMOTE 0)
  set(OSSIA_DISABLE_QT_PLUGIN 0)
  set(OSSIA_DNSSD 1)
endif()

if(OSSIA_PYTHON_ONLY)
  set(OSSIA_NO_INSTALL 1)
  set(OSSIA_STATIC 1)
  set(OSSIA_DATAFLOW 0)
  set(OSSIA_EDITOR 0)
  set(OSSIA_JAVA 0)
  set(OSSIA_PD 0)
  set(OSSIA_MAX 0)
  set(OSSIA_PYTHON 1)
  set(OSSIA_QT 0)
  set(OSSIA_C 0)
  set(OSSIA_CPP 0)
  set(OSSIA_UNITY3D 0)
  set(OSSIA_QML 0)
  set(OSSIA_QML_SCORE 0)
  set(OSSIA_PROTOCOL_AUDIO 0)
  set(OSSIA_PROTOCOL_MIDI 1)
  set(OSSIA_PROTOCOL_OSC 1)
  set(OSSIA_PROTOCOL_MINUIT 1)
  set(OSSIA_PROTOCOL_OSCQUERY 1)
  set(OSSIA_PROTOCOL_HTTP 0)
  set(OSSIA_PROTOCOL_WEBSOCKETS 0)
  set(OSSIA_PROTOCOL_SERIAL 0)
  set(OSSIA_PROTOCOL_PHIDGETS 0)
  set(OSSIA_PROTOCOL_LEAPMOTION 0)
  set(OSSIA_PROTOCOL_JOYSTICK 0)
  set(OSSIA_PROTOCOL_WIIMOTE 0)
  set(OSSIA_DISABLE_QT_PLUGIN 0)
  set(OSSIA_DNSSD 1)
endif()

if(OSSIA_QML_ONLY)
  set(OSSIA_NO_INSTALL 0)
  set(OSSIA_STATIC 0)
  set(OSSIA_DATAFLOW 0)
  set(OSSIA_EDITOR 0)
  set(OSSIA_JAVA 0)
  set(OSSIA_PD 0)
  set(OSSIA_MAX 0)
  set(OSSIA_PYTHON 0)
  set(OSSIA_QT 0)
  set(OSSIA_C 0)
  set(OSSIA_CPP 0)
  set(OSSIA_UNITY3D 0)
  set(OSSIA_QML 1)
  set(OSSIA_QML_SCORE 0)
  set(OSSIA_PROTOCOL_AUDIO 0)
  set(OSSIA_PROTOCOL_MIDI 0)
  set(OSSIA_PROTOCOL_OSC 1)
  set(OSSIA_PROTOCOL_MINUIT 1)
  set(OSSIA_PROTOCOL_OSCQUERY 1)
  set(OSSIA_PROTOCOL_HTTP 0)
  set(OSSIA_PROTOCOL_WEBSOCKETS 0)
  set(OSSIA_PROTOCOL_SERIAL 0)
  set(OSSIA_PROTOCOL_PHIDGETS 0)
  set(OSSIA_PROTOCOL_LEAPMOTION 0)
  set(OSSIA_PROTOCOL_JOYSTICK 0)
  set(OSSIA_PROTOCOL_WIIMOTE 0)
  set(OSSIA_DISABLE_QT_PLUGIN 0)
  set(OSSIA_DNSSD 1)
endif()

if(OSSIA_UNITY3D_ONLY)
  set(OSSIA_NO_INSTALL 0)
  set(OSSIA_STATIC 0)
  set(OSSIA_DATAFLOW 0)
  set(OSSIA_EDITOR 0)
  set(OSSIA_JAVA 0)
  set(OSSIA_PD 0)
  set(OSSIA_MAX 0)
  set(OSSIA_PYTHON 0)
  set(OSSIA_QT 0)
  set(OSSIA_C 0)
  set(OSSIA_CPP 0)
  set(OSSIA_UNITY3D 1)
  set(OSSIA_QML 0)
  set(OSSIA_QML_SCORE 0)
  set(OSSIA_PROTOCOL_AUDIO 0)
  set(OSSIA_PROTOCOL_MIDI 0)
  set(OSSIA_PROTOCOL_OSC 1)
  set(OSSIA_PROTOCOL_MINUIT 1)
  set(OSSIA_PROTOCOL_OSCQUERY 1)
  set(OSSIA_PROTOCOL_HTTP 0)
  set(OSSIA_PROTOCOL_WEBSOCKETS 0)
  set(OSSIA_PROTOCOL_SERIAL 0)
  set(OSSIA_PROTOCOL_PHIDGETS 0)
  set(OSSIA_PROTOCOL_LEAPMOTION 0)
  set(OSSIA_PROTOCOL_JOYSTICK 0)
  set(OSSIA_PROTOCOL_WIIMOTE 0)
  set(OSSIA_DISABLE_QT_PLUGIN 0)
  set(OSSIA_DNSSD 1)
endif()

if(OSSIA_QML)
    set(OSSIA_OSX_FAT_LIBRARIES 0)
    set(OSSIA_QT 1)
    set(OSSIA_NO_SONAME 1)
endif()
if(OSSIA_PD)
  set(OSSIA_HIDE_ALL_SYMBOLS 1)
endif()
if(OSSIA_MAX)
    set(OSSIA_OSX_FAT_LIBRARIES 1)
    set(OSSIA_QT 0)
    set(OSSIA_HIDE_ALL_SYMBOLS 1)
endif()
if(OSSIA_UNITY3D)
    set(OSSIA_OSX_FAT_LIBRARIES 1)
    set(OSSIA_QT 0)
    set(OSSIA_NO_SONAME 1)
    set(OSSIA_C 1)
endif()
if(OSSIA_JAVA)
    set(OSSIA_OSX_FAT_LIBRARIES 1)
    set(OSSIA_QT 0)
    set(OSSIA_NO_SONAME 1)
    set(OSSIA_C 1)
endif()
if(OSSIA_OSX_FAT_LIBRARIES)
    string(REGEX MATCH "10.[0-9][0-9]" MACOS_SDK_VERSION "${CMAKE_OSX_SYSROOT}")
    if(MACOS_SDK_VERSION VERSION_LESS 10.14)
      set(CMAKE_OSX_ARCHITECTURES "i386;x86_64")
      set(OSSIA_DISABLE_COTIRE 1)
    else()
      message("-- WARNING: macOS 10.14 / Xcode 10 do not support building 32-bit anymore.")
    endif()
endif()
if(OSSIA_NO_QT)
  set(OSSIA_QT 0)
endif()
if(OSSIA_OSX_RETROCOMPATIBILITY)
  set(CMAKE_OSX_DEPLOYMENT_TARGET 10.9)
endif()

include(Sanitize)
include(DebugMode)
include(UseGold)
include(LinkerWarnings)

if(OSSIA_MOST_STATIC)
    set(OSSIA_STATIC ON)
    set(CMAKE_LINK_SEARCH_END_STATIC ON)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

if(OSSIA_MAX OR OSSIA_PD AND WIN32)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
  set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /MT")

  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /MT")
endif()

# System detection
include(ProcessorCount)
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wmisleading-indentation" SUPPORTS_MISLEADING_INDENT_FLAG)
check_cxx_compiler_flag("-Wl,-z,defs" WL_ZDEFS_SUPPORTED)

if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
  set(LINKER_IS_LLD 0)
  set(LINKER_IS_GOLD 0)
  set(OSSIA_PD 0)
  set(OSSIA_PYTHON 0)
  set(OSSIA_DATAFLOW 0)
  set(OSSIA_PROTOCOL_MIDI 0)
  set(OSSIA_DISABLE_COTIRE 1)
  set(ANDROID 1)
else()
  if(UNIX AND NOT APPLE)
      find_program(LSB_RELEASE lsb_release)
      if(LSB_RELEASE)
        execute_process(COMMAND ${LSB_RELEASE} -i
            OUTPUT_VARIABLE RELEASE_CODENAME
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
      endif()
  endif()

  macro(check_cxx_linker_flag _Flag _Var)
    set(old_link_libs "${CMAKE_REQUIRED_LIBRARIES}")
    set(CMAKE_REQUIRED_LIBRARIES ${old_link_libs} "${_Flag}")
    check_cxx_compiler_flag("${_Flag}" ${_Var})
    set(CMAKE_REQUIRED_LIBRARIES "${old_link_libs}")
  endmacro()

  if(OSSIA_USE_FAST_LINKER)
    check_cxx_linker_flag("-fuse-ld=lld" LLD_LINKER_SUPPORTED)
    check_cxx_linker_flag("-fuse-ld=gold" GOLD_LINKER_SUPPORTED)

    if(OSSIA_SANITIZE AND NOT APPLE)
      set(LLD_LINKER_SUPPORTED 0)
    endif()
    if(LLD_LINKER_SUPPORTED)
      set(LINKER_IS_LLD 1 CACHE INTERNAL "use lld linker")
    elseif(GOLD_LINKER_SUPPORTED)
      set(LINKER_IS_GOLD 1 CACHE INTERNAL "use gold linker")
    endif()

    if(LINKER_IS_GOLD)
      check_cxx_linker_flag("-fuse-ld=gold -Wl,--threads -Wl,--thread-count,2" LINKER_THREADS_SUPPORTED)
      check_cxx_linker_flag("-fuse-ld=gold -Wl,--gdb-index" GDB_INDEX_SUPPORTED)
    elseif(LINKER_IS_LLD)
      check_cxx_linker_flag("-fuse-ld=lld -Wl,--threads" LINKER_THREADS_SUPPORTED)
      check_cxx_linker_flag("-fuse-ld=lld -Wl,--gdb-index" GDB_INDEX_SUPPORTED)
    endif()
  endif()
endif()

if(OSSIA_SPLIT_DEBUG)
  set(DEBUG_SPLIT_FLAG "-gsplit-dwarf")
  if(NOT APPLE AND NOT MINGW)
    set(GOLD_FLAGS
#      -Wa,--compress-debug-sections
#      -Wl,--compress-debug-sections=zlib
      -Wl,--dynamic-list-cpp-new
      -Wl,--dynamic-list-cpp-typeinfo
    )
    if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
      set(GOLD_FLAGS ${GOLD_FLAGS} -Wno-unused-command-line-argument)
    endif()
  endif()

  if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(GOLD_FLAGS ${GOLD_FLAGS}
      -ggdb
    )
  endif()

  if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    set(GOLD_FLAGS ${GOLD_FLAGS}
      -ggdb
      )
  endif()

endif()
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES ".*arm.*")
    set(OSSIA_ARCHITECTURE arm)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES ".*aarch64.*")
    set(OSSIA_ARCHITECTURE arm)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES ".*64.*")
    set(OSSIA_ARCHITECTURE amd64)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES ".*86.*")
    set(OSSIA_ARCHITECTURE x86)
else()
    message("Could not determine target architecture")
    return()
endif()

# Common setup
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
if(MSVC)
  set(CMAKE_CXX_FLAGS "/std:c++latest ${CMAKE_CXX_FLAGS}")
else()
  set(CMAKE_CXX_FLAGS "-std=c++1z ${CMAKE_CXX_FLAGS}")
endif()

# So that make install after make all_unity does not rebuild everything :
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY True)

# We disable debug infos on OS X on travis because it takes up too much space
if(OSSIA_CI AND APPLE OR OSSIA_NO_DEBUG_INFO)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g0")
endif()

if(OSSIA_CI)
  set(OSSIA_USE_FAST_LINKER ON)
endif()

if(OSSIA_STATIC)
  set(BUILD_SHARED_LIBS OFF)
  set(OSSIA_FRAMEWORK OFF)
else()
  set(BUILD_SHARED_LIBS ON)
endif()

if(OSSIA_COVERAGE)
  include(CodeCoverage)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_COVERAGE}")
endif()

# Compiler & linker flags
if(MSVC)
  set(CMAKE_CXX_FLAGS "-DNOGDI -DLF_FACESIZE=32 ${CMAKE_CXX_FLAGS}")
  set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /PDBCompress /OPT:REF /OPT:ICF")
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /PDBCompress /OPT:REF /OPT:ICF")
  set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} /PDBCompress /OPT:REF /OPT:ICF")

  set(OSSIA_COMPILE_OPTIONS
      "/wd4065" # switch statement contains default but no case labels
      "/wd4068" # pragma mark -
      "/wd4221" # this object file does not define any previously undefined public symbols
      "/wd4250" # inherits via dominance
      "/wd4251" # DLL stuff
      "/wd4267" # initializing: conversion from size_t to int, possible loss of data or 'argument': conversion from size_t to ..., possible loss of data
      "/wd4275" # DLL stuff
      "/wd4244" # return : conversion from foo to bar, possible loss of data
      "/wd4305" # argument : truncation from double to float
      "/wd4503" # decorated name length exceeded
      "/wd4624" # destructor was implicityl defined as deleted
      "/wd4800" # conversion from int to bool, performance warning
      "/wd4804" # unsafe mix of const bool <= const int
      "/wd4805" # unsafe mix of const bool == const int
      "/wd4996" # SCL_SECURE_NO_WARNINGS
      "/bigobj"
      ${OSSIA_LINK_OPTIONS}
  )
else()
  if(CMAKE_BUILD_TYPE MATCHES Release)
    set(OSSIA_COMPILE_OPTIONS
      ${OSSIA_COMPILE_OPTIONS}
      -fno-math-errno
    )
  endif()

  set(OSSIA_LINK_OPTIONS
    -ffunction-sections
    -fdata-sections
  )

  if(NOT WIN32)
    if(NOT APPLE)
      set(OSSIA_LINK_OPTIONS
        -Wl,--gc-sections
        -Wl,--as-needed
      )
    else()
      set(OSSIA_LINK_OPTIONS
        -Wl,-dead_strip
      )
    endif()
  endif()

  if(CMAKE_COMPILER_IS_GNUCXX)
    set(OSSIA_LINK_OPTIONS ${OSSIA_LINK_OPTIONS}
      -fvar-tracking-assignments
    )
    if(NOT OSSIA_SPLIT_DEBUG)
      set(OSSIA_LINK_OPTIONS ${OSSIA_LINK_OPTIONS}
        -Wl,-Bsymbolic-functions
      )

      if(GDB_INDEX_SUPPORTED AND NOT OSSIA_SANITIZE)
        set(OSSIA_LINK_OPTIONS ${OSSIA_LINK_OPTIONS}
            ${DEBUG_SPLIT_FLAG}
            -Wl,--gdb-index
        )
      endif()
    endif()
  endif()

  if(LINKER_IS_GOLD)
    set(OSSIA_LINK_OPTIONS ${OSSIA_LINK_OPTIONS} ${GOLD_FLAGS})
  endif()

  if(OSSIA_MOST_STATIC)
    set(OSSIA_LINK_OPTIONS ${OSSIA_LINK_OPTIONS} -static -static-libgcc -static-libstdc++)
  endif()

  if(OSSIA_CI)
    set(OSSIA_LINK_OPTIONS ${OSSIA_LINK_OPTIONS} -s)
  endif()

  if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    set(OSSIA_COMPILE_OPTIONS ${OSSIA_COMPILE_OPTIONS}
      -Wno-gnu-statement-expression
      -Wno-four-char-constants
      -Wno-cast-align
      -Wno-unused-local-typedef
      #-Wweak-vtables
    )
  endif()
  set(OSSIA_COMPILE_OPTIONS
      ${OSSIA_COMPILE_OPTIONS}
      -Wall
      -Wextra
      -Wno-unused-parameter
      -Wno-unknown-pragmas
      -Wno-missing-braces
      -Wnon-virtual-dtor
      -pedantic
      -Wunused
      -Woverloaded-virtual
      -pipe
      -Werror=return-type
      -Werror=trigraphs
      -Wmissing-field-initializers
      ${OSSIA_LINK_OPTIONS}
  )

  if(OSSIA_CI)
    if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
          set(OSSIA_LINK_OPTIONS ${OSSIA_LINK_OPTIONS} -Wl,-S)
    endif()
  endif()

  if("${SUPPORTS_MISLEADING_INDENT_FLAG}")
      set(OSSIA_COMPILE_OPTIONS ${OSSIA_COMPILE_OPTIONS} -Wmisleading-indentation)
  endif()

#    if(APPLE)
#        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-warn_weak_exports")
#        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-warn_weak_exports")
#        set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-warn_weak_exports")
#    endif()
endif()

if(OSSIA_LTO)
  setup_lto()
endif()
