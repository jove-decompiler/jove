if (NOT DEFINED LLVM_VERSION_MAJOR)
  message(FATAL_ERROR "This project needs to be built as an LLVM project")
endif()

option(JOVE_HAVE_MEMFD "memfd_create(2) exists, implies Linux >= 3.17" OFF)

# we are *not* using libc++, so the following should be O.K.
add_definitions(-DBOOST_STACKTRACE_LIBCXX_RUNTIME_MAY_CAUSE_MEMORY_LEAK)

# Find boost.
#
# By default, we build a bundled one and statically-link the library
# to jove. If you want to link to the system's libboost_-*.so, pass
# -DJOVE_USE_SYSTEM_BOOST=ON.
option(JOVE_USE_SYSTEM_BOOST "Use system or vendored boost" OFF)
if(JOVE_USE_SYSTEM_BOOST)
  find_package(boost_system 1.85 REQUIRED)
  find_package(boost_filesystem 1.85 REQUIRED)
  find_package(boost_serialization 1.85 REQUIRED)
else()
  function(jove_add_boost)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_TESTING OFF)
    set(BOOST_INCLUDE_LIBRARIES system filesystem serialization interprocess dll graph format icl lockfree stacktrace)
    set(BOOST_STACKTRACE_ENABLE_BACKTRACE      ON  CACHE BOOL "" FORCE)
    set(BOOST_STACKTRACE_ENABLE_ADDR2LINE      OFF CACHE BOOL "" FORCE)
    set(BOOST_STACKTRACE_ENABLE_NOOP           OFF CACHE BOOL "" FORCE)
    set(BOOST_STACKTRACE_ENABLE_BASIC          OFF CACHE BOOL "" FORCE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(mips|mipsel|mips64el)$")
      #
      # --wrap appears to be broken on MIPS
      #
      set(BOOST_STACKTRACE_ENABLE_FROM_EXCEPTION OFF CACHE BOOL "" FORCE)
    else()
      set(BOOST_STACKTRACE_ENABLE_FROM_EXCEPTION ON CACHE BOOL "" FORCE)
    endif()
    add_subdirectory(boost EXCLUDE_FROM_ALL)
    #target_compile_definitions(boost PRIVATE BOOST_NO_RTTI)
  endfunction()

  jove_add_boost()
endif()

option(JOVE_USE_SYSTEM_TBB "Use system or vendored TBB" OFF)

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(mips|mipsel|mips64el)$")
  if(JOVE_USE_SYSTEM_TBB)
    find_package(TBB REQUIRED)
  else()
    function(jove_add_tbb)
      # this is so tbb/src/tbb/semaphore.h doesn't include itself...
      set(CMAKE_INCLUDE_CURRENT_DIR OFF)

      set(BUILD_SHARED_LIBS OFF)
      set(TBB_TEST OFF CACHE INTERNAL "")
      set(TBB_STRICT OFF CACHE INTERNAL "")
      add_subdirectory(oneTBB EXCLUDE_FROM_ALL)
      target_compile_definitions(tbb PRIVATE __TBB_DYNAMIC_LOAD_ENABLED=0)
    endfunction()

    jove_add_tbb()
  endif()
endif()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86|i[3-6]86|x86_64)$")
  function(jove_add_ipt)
    set(CMAKE_INCLUDE_CURRENT_DIR OFF)

    set(PTXED OFF CACHE INTERNAL "")
#   SET(XED_INCLUDE xed/obj/wkit/include/xed)
#   SET(XED_LIBDIR xed/obj)
    set(PTDUMP ON CACHE INTERNAL "")
    set(PTSEG OFF CACHE INTERNAL "")
    SET(SIDEBAND ON CACHE INTERNAL "")
    SET(PEVENT ON CACHE INTERNAL "")
    SET(FEATURE_THREADS ON CACHE INTERNAL "")
    SET(FEATURE_ELF OFF CACHE INTERNAL "")
    add_subdirectory(libipt EXCLUDE_FROM_ALL)
  endfunction()

  message(STATUS "Building for an x86 target")

  jove_add_ipt()
endif ()

set(JOVE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(tools)
