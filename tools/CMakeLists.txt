set(JOVE_VERSION "v0.94")

# for some reason backtrace.h isn't found
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
  set(BACKTRACE_HEADER "/usr/lib/gcc/x86_64-linux-gnu/12/include/backtrace.h")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  set(BACKTRACE_HEADER "/usr/lib/gcc-cross/aarch64-linux-gnu/12/include/backtrace.h")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3-6]86")
  set(BACKTRACE_HEADER "/usr/lib/gcc-cross/i686-linux-gnu/12/include/backtrace.h")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "mipsel")
  set(BACKTRACE_HEADER "/usr/lib/gcc-cross/mipsel-linux-gnu/12/include/backtrace.h")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "mips64el")
  set(BACKTRACE_HEADER "/usr/lib/gcc-cross/mips64el-linux-gnuabi64/12/include/backtrace.h")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")
  set(BACKTRACE_HEADER "/usr/lib/gcc-cross/mips-linux-gnu/12/include/backtrace.h")
else()
  message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(JOVE_TOOL_FLAGS
  "-fwrapv"

  "-D_GNU_SOURCE"
  "-D_FILE_OFFSET_BITS=64"

  "-DBOOST_ICL_USE_STATIC_BOUNDED_INTERVALS"
  "-DBOOST_UNORDERED_DISABLE_REENTRANCY_CHECK"
  "-DBOOST_STACKTRACE_USE_BACKTRACE"
  "-DBOOST_STACKTRACE_STATIC_LINK"
  "-DBOOST_STACKTRACE_BACKTRACE_INCLUDE_FILE=\"${BACKTRACE_HEADER}\""

  # opiniated stuff...
  "-Werror=format"
  "-Werror=return-stack-address"
  "-Werror=return-type"
  "-Wno-bit-int-extension"
  "-Wno-bitwise-instead-of-logical"
  "-Wno-c99-designator"
  "-Wno-c99-extensions"
  "-Wno-cast-qual"
  "-Wno-deprecated-declarations"
  "-Wno-gnu-anonymous-struct"
  "-Wno-gnu-case-range"
  "-Wno-gnu-designator"
  "-Wno-gnu-statement-expression"
  "-Wno-gnu-statement-expression-from-macro-expansion"
  "-Wno-initializer-overrides"
  "-Wno-nested-anon-types"
  "-Wno-sign-compare"
  "-Wno-unused-lambda-capture"
  "-Wno-missing-template-arg-list-after-template-kw"
  "-Wno-gnu-label-as-value"
)

set(JOVE_ALL_TARGETS
  i386
  x86_64
  aarch64
  mipsel
  mips
  mips64el
)

option(JOVE_STATIC_BUILD "Building with -static" ON)
option(JOVE_SANITIZE_THREAD "Building with -fsanitize=thread" OFF)

set(JOVE_TARGETS_TO_BUILD "all"
    CACHE STRING "Semicolon-separated list of targets to build, or \"all\".")

if( JOVE_TARGETS_TO_BUILD STREQUAL "all" )
  set( JOVE_TARGETS_TO_BUILD ${JOVE_ALL_TARGETS} )
else()
  foreach(t ${JOVE_TARGETS_TO_BUILD})
    list(FIND JOVE_ALL_TARGETS ${t} idx)

    if( idx LESS 0 )
      message(FATAL_ERROR "Target ${t} is not a valid target.")
    endif()
  endforeach()
endif()

set(JOVE_SOURCES
    ../core/tbb_hacks.cpp # we'd like to have this first to disable TBB...
    ../core/B.cpp
    ../core/add.cpp
    ../core/analyze.cpp
    ../core/binary.cpp
    ../core/block.cpp
    ../core/calls.cpp
    ../core/coff.cpp
    ../core/crash.cpp
    ../core/crypto.cpp
    ../core/byval.cpp
    ../core/disas.cpp
    ../core/elf.cpp
    ../core/explore.cpp
    ../core/fd.cpp
    ../core/flow.cpp
    ../core/function.cpp
    ../core/hash.cpp
    ../core/ida.cpp
    ../core/jv.cpp
    ../core/locator.cpp
    ../core/llvm.cpp
    ../core/mmap.cpp
    ../core/objdump.cpp
    ../core/perf.cpp
    ../core/pipe.cpp
    ../core/process.cpp
    ../core/portable_binary_iarchive.cpp
    ../core/portable_binary_oarchive.cpp
    ../core/ptrace.cpp
    ../core/pidfd.cpp
    ../core/recovery.cpp
    ../core/recompile.cpp
    ../core/redirect.cpp
    ../core/reflink.cpp
    ../core/score.cpp
    ../core/sret.cpp
    ../core/serialize.cpp
    ../core/sideband.cpp
    ../core/sjlj.cpp
    ../core/symbolizer.cpp
    ../core/tcg.cpp
    ../core/temp.cpp
    ../core/tool.cpp # has to come before all the tools
    ../core/triple.cpp
    ../core/util.cpp
    ../core/vdso.cpp
    ../core/win.cpp
    ../core/wine.cpp
    check-helper.cpp
    dump-vdso.cpp
    jove-add.cpp
    jove-addr2off.cpp
    jove-analyze.cpp
    jove-block.cpp
    jove-bootstrap.cpp
    jove-callstack.cpp
    jove-cfg.cpp
    jove-decompile.cpp
    jove-dig.cpp
    jove-dump.cpp
    jove-extract.cpp
    jove-function.cpp
    jove-ida.cpp
    jove-init.cpp
    jove-invalidate.cpp
    jove-ipt.cpp
    jove-loop.cpp
    jove-off2addr.cpp
    jove-readtrace.cpp
    jove-recompile.cpp
    jove-recover.cpp
    jove-run.cpp
    jove-sanity.cpp
    jove-scan.cpp
    jove-score.cpp
    jove-serialize.cpp
    jove-llvm.cpp
    jove-server.cpp
    jove-stub.cpp
    jove-trace.cpp
    jove-trace2addrs.cpp
    jove-trace2asm.cpp
    jove-trace2lines.cpp
    jove-unlock.cpp
    jove-unserialize.cpp
    jove-unstub.cpp
    jv2xml.cpp
    llknife.cpp
    tcgdump.cpp
)

function(tool_for_arch arch arch_extra_cflags qemu_build_dir)
  string(TOUPPER "${arch}" uc_arch)

  add_llvm_tool(jove-${arch} ${JOVE_SOURCES})

  target_link_libraries(jove-${arch} PRIVATE
    -Wl,--push-state,--whole-archive
    ${qemu_build_dir}/libqemu4jove-${arch}.a
    -Wl,--pop-state

    -pthread
    glib-2.0

    atomic
    zlibstatic
    dl
    backtrace
    ffi
  )

  target_link_libraries(jove-${arch} PRIVATE Boost::system)
  target_link_libraries(jove-${arch} PRIVATE Boost::filesystem)
  target_link_libraries(jove-${arch} PRIVATE Boost::serialization)
  target_link_libraries(jove-${arch} PRIVATE Boost::interprocess)
  target_link_libraries(jove-${arch} PRIVATE Boost::dll)
  target_link_libraries(jove-${arch} PRIVATE Boost::graph)
  target_link_libraries(jove-${arch} PRIVATE Boost::format)
  target_link_libraries(jove-${arch} PRIVATE Boost::icl)
  target_link_libraries(jove-${arch} PRIVATE Boost::lockfree)
  target_link_libraries(jove-${arch} PRIVATE Boost::scope)
# target_link_libraries(jove-${arch}
#   PUBLIC
#     Boost::stacktrace
#     Boost::stacktrace_from_exception
# )

  target_link_libraries(jove-${arch} PRIVATE
    -Wl,--push-state,--whole-archive
    ${CMAKE_BINARY_DIR}/llvm/lib/libboost_stacktrace_from_exception.a
    ${CMAKE_BINARY_DIR}/llvm/lib/libboost_stacktrace_backtrace.a
    -Wl,--pop-state
  )

  # this is the magic we need for static-linking
  target_link_options(jove-${arch} PRIVATE  "-Wl,--wrap=__cxa_allocate_exception")

  if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(mips|mipsel|mips64el)$")
    target_link_libraries(jove-${arch} PRIVATE TBB::tbb)
  endif()

  target_include_directories(jove-${arch} PRIVATE ${JOVE_SRC_DIR}/boost/libs/stacktrace/include)

  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86|i[3-6]86|x86_64)$")
    target_link_libraries(jove-${arch} PRIVATE libipt)
    target_link_libraries(jove-${arch} PRIVATE libipt-sb)
    target_link_libraries(jove-${arch} PRIVATE uring)
    target_include_directories(jove-${arch} PRIVATE ${JOVE_SRC_DIR}/libipt/libipt/internal/include)
    target_include_directories(jove-${arch} PRIVATE ${CMAKE_BINARY_DIR}/llvm/projects/jove/libipt/libipt/include)
    target_include_directories(jove-${arch} PRIVATE ${CMAKE_BINARY_DIR}/llvm/projects/jove/libipt/sideband/include)
    target_include_directories(jove-${arch} PRIVATE ${JOVE_SRC_DIR}/libipt/pevent/include)
  endif()

  if(JOVE_SANITIZE_THREAD)
    add_definitions(-DJOVE_TSAN)
    add_definitions(-DBOOST_UNORDERED_THREAD_SANITIZER)
  endif()

  if(JOVE_STATIC_BUILD)
    target_link_options(jove-${arch} PRIVATE "-static")

    # force CMake to write (an empty) RPATH at build time rather than patch at install
    set_target_properties(jove-${arch} PROPERTIES
      INSTALL_RPATH ""          # don't embed RPATH
      SKIP_BUILD_RPATH  TRUE    # don't put any build-RPATH in the binary either
    )
  endif()

  target_link_options(jove-${arch} PRIVATE "-pie")

  target_include_directories(jove-${arch} PRIVATE
    ${JOVE_SRC_DIR}/lib/arch/${arch}
    ${JOVE_SRC_DIR}/bin/${arch}
    ${JOVE_SRC_DIR}/bin
  )

  target_compile_options(jove-${arch} PRIVATE
    -DTARGET_${uc_arch}
    -DTARGET_ARCH_NAME=\"${arch}\"
    -DJOVE_VERSION=\"${JOVE_VERSION}\"
    ${JOVE_TOOL_FLAGS}
    ${arch_extra_cflags}
  )

  if (JOVE_HAVE_MEMFD)
    target_compile_options(jove-${arch} PRIVATE -DJOVE_HAVE_MEMFD)
  endif()

endfunction()

#
# Insist on C++ 20 features.
#
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

#
# common include directories
#
include_directories(../include)
include_directories(../lib)
include_directories(../core)

#
# LLVM components needed
#
set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  object
  passes
  objcarcopts
  coroutines
  symbolize
)

#
# create target for each architecture
#
set(JOVE_mipsel_extra_cflags "-DTARGET_MIPS32")
set(JOVE_mips_extra_cflags "-DTARGET_MIPS32")
set(JOVE_mips64el_extra_cflags "-DTARGET_MIPS64")

if(CMAKE_CROSSCOMPILING)
  list(FIND JOVE_ALL_TARGETS "${LLVM_TARGET_ARCH}" idx)

  if( idx LESS 0 )
    message(FATAL_ERROR "Target ${LLVM_TARGET_ARCH} is not a valid target.")
  endif()

  set(JOVE_QEMU_BUILD_DIR_NAME "${LLVM_TARGET_ARCH}_build")
else()
  set(JOVE_QEMU_BUILD_DIR_NAME "build")
endif()

foreach(arch ${JOVE_TARGETS_TO_BUILD})
  tool_for_arch("${arch}" "${JOVE_${arch}_extra_cflags}" "${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}")
endforeach()
