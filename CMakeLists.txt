if (NOT DEFINED LLVM_VERSION_MAJOR)
  message(FATAL_ERROR "This project needs to be built as an LLVM project")
endif()

if (LLVM_VERSION_MAJOR LESS 8)
  message(FATAL_ERROR "This project isn't buldable with LLVM < 8.0.0.")
elseif (LLVM_VERSION_MAJOR LESS 10)
  message(WARNING "Building with LLVM < 10.0.0 is at your own risk.")
endif()

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
    set(BOOST_INCLUDE_LIBRARIES system filesystem serialization interprocess dll graph format icl lockfree)
    add_subdirectory(boost EXCLUDE_FROM_ALL)
    #target_compile_definitions(boost PRIVATE BOOST_NO_RTTI)
  endfunction()

  jove_add_boost()
endif()

# Find TBB. TBB (OneTBB or Intel TBB) is a high-level threading library.
#
# By default, we build a bundled one and statically-link the library
# to jove. If you want to link to the system's libtbb2.so, pass
# -DJOVE_USE_SYSTEM_TBB=ON.
option(JOVE_USE_SYSTEM_TBB "Use system or vendored TBB" OFF)
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

set(JOVE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(tools)
