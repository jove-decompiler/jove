option(JOVE_STATIC_BUILD "Building with -static" ON)
option(JOVE_SANITIZE_THREAD "Building with -fsanitize=thread" OFF)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(mips|mipsel|mips64el)$") # FIXME
# no backend
llvm_map_components_to_libnames(llvm_libs
  AllTargetsAsmParsers
  AllTargetsCodeGens
  AllTargetsDescs
  AllTargetsDisassemblers
  AllTargetsInfos
  BitReader
  Core
  MCDisassembler
  Object
  Support
  Target
)
else()
llvm_map_components_to_libnames(llvm_libs
  AllTargetsAsmParsers
  AllTargetsCodeGens
  AllTargetsDescs
  AllTargetsDisassemblers
  AllTargetsInfos
  BitReader
  Core
  MCDisassembler
  Object
  Support
  Target
  Passes
)
endif()

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

target_compile_definitions(boost_stacktrace_backtrace PRIVATE
  "BOOST_STACKTRACE_BACKTRACE_INCLUDE_FILE=<${BACKTRACE_HEADER}>"
)

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(mips|mipsel|mips64el)$") # [no threads] (FIXME) # lld's --wrap is broken on mips (FIXME)
if(JOVE_STATIC_BUILD)
  target_compile_definitions(boost_stacktrace_from_exception PRIVATE BOOST_STATIC_EXECUTABLE)
endif()
endif()

set(JOVE_TOOL_FLAGS
  "-fno-strict-overflow"
  "-fno-strict-aliasing"

  "-D_GNU_SOURCE"
  "-D_FILE_OFFSET_BITS=64"
  "-D_LARGEFILE64_SOURCE"

  "-DBOOST_ICL_USE_STATIC_BOUNDED_INTERVALS"
  "-DBOOST_UNORDERED_DISABLE_REENTRANCY_CHECK"
  "-DBOOST_STACKTRACE_USE_BACKTRACE"
  "-DBOOST_STACKTRACE_STATIC_LINK"
# "-DBOOST_ENABLE_ASSERT_HANDLER"

# "-DTBB_USE_ASSERT=1"
# "-DBOOST_DISABLE_ASSERTS"

  # opiniated stuff...
  "-Werror=format"
  "-Werror=return-stack-address"
  "-Werror=return-type"
  "-Wno-deprecated-declarations"
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
    ../core/death.cpp # PR_SET_PDEATHSIG before any threads are created
    ../core/tbb_hacks.cpp # we'd like to have this first to disable TBB...
    ../core/B.cpp
    ../core/add.cpp
    ../core/analyze.cpp
    ../core/binary.cpp
    ../core/block.cpp
    ../core/calls.cpp
    ../core/coff.cpp
    ../core/cpu.cpp
    ../core/crash.cpp
    ../core/crypto.cpp
    ../core/byval.cpp
    ../core/disas.cpp
    ../core/elf.cpp
    ../core/explore.cpp
    ../core/fd.cpp
    ../core/flow.cpp
    ../core/fork.cpp
    ../core/function.cpp
    ../core/hash.cpp
    ../core/ida.cpp
    ../core/jv.cpp
    ../core/locator.cpp
    ../core/llvm.cpp
    ../core/mt.cpp
    ../core/objdump.cpp
    ../core/perf.cpp
    ../core/pipe.cpp
    ../core/process.cpp
    ../core/prefetch.cpp
    ../core/ptrace.cpp
    ../core/pidfd.cpp
    ../core/recovery.cpp
    ../core/recompile.cpp
    ../core/redirect.cpp
    ../core/reflink.cpp
    ../core/robust.cpp
    ../core/score.cpp
    ../core/sret.cpp
    ../core/serialize.cpp
    ../core/sideband.cpp
    ../core/sjlj.cpp
    ../core/symbolizer.cpp
    ../core/tcg.cpp
    ../core/temp.cpp
    ../core/tool.cpp # has to come before all the tools
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
    tcgdump.cpp
)

function(tool_for_arch arch arch_extra_cflags qemu_build_dir)
  string(TOUPPER "${arch}" uc_arch)

  add_llvm_executable(jove-${arch} ${JOVE_SOURCES})

  target_link_libraries(jove-${arch} PRIVATE ${llvm_libs})

# set_source_files_properties(jove-off2addr.cpp
#   PROPERTIES COMPILE_FLAGS "-Xclang -fdump-record-layouts"
# )

  target_link_libraries(jove-${arch} PRIVATE
    -pthread

    -Wl,--push-state,--whole-archive
    ${qemu_build_dir}/libqemu4jove-${arch}.a

#   ${qemu_build_dir}/qemu4jove-${arch}.cut.bc
#   ${qemu_build_dir}/libqemu4jove-${arch}-native.a
    -Wl,--pop-state

    glib-2.0

    atomic
    zlibstatic
    dl
    backtrace
    ffi
  )

  #
  # <3 boost
  #
  target_link_libraries(jove-${arch}
    PRIVATE
      Boost::system
      Boost::filesystem
      Boost::serialization
      Boost::interprocess
      Boost::dll
      Boost::graph
      Boost::format
      Boost::icl
      Boost::lockfree
      Boost::scope
#     Boost::stacktrace
#     Boost::stacktrace_from_exception
  )

  target_link_libraries(jove-${arch} PRIVATE
    -Wl,--push-state,--whole-archive
    ${CMAKE_BINARY_DIR}/llvm/lib/libboost_stacktrace_backtrace.a
    -Wl,--pop-state
  )

  if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(mips|mipsel|mips64el)$") # [no threads] (FIXME) # lld's --wrap is broken on mips (FIXME)
    if(JOVE_STATIC_BUILD)
      # this is the magic we need for static-linking
      target_link_options(jove-${arch} PRIVATE  "-Wl,--wrap=__cxa_allocate_exception")
    endif()

    target_link_libraries(jove-${arch} PRIVATE
      -Wl,--push-state,--whole-archive
      ${CMAKE_BINARY_DIR}/llvm/lib/libboost_stacktrace_from_exception.a
      -Wl,--pop-state
    )
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
    target_compile_definitions(jove-${arch} PRIVATE JOVE_TSAN)
    target_compile_definitions(jove-${arch} PRIVATE BOOST_UNORDERED_THREAD_SANITIZER)
  endif()

  if(JOVE_STATIC_BUILD)
    target_link_options(jove-${arch} PRIVATE "-static")

    # force CMake to write (an empty) RPATH at build time rather than patch at install
    set_target_properties(jove-${arch} PROPERTIES
      INSTALL_RPATH ""          # don't embed RPATH
      SKIP_BUILD_RPATH  TRUE    # don't put any build-RPATH in the binary either
    )
  endif()

  target_include_directories(jove-${arch} PRIVATE
    ${JOVE_SRC_DIR}/lib/arch/${arch}
    ${JOVE_SRC_DIR}/bin/${arch}
    ${JOVE_SRC_DIR}/bin
  )

  target_compile_options(jove-${arch} PRIVATE
    -DTARGET_${uc_arch}
    -DTARGET_ARCH_NAME=\"${arch}\"
    ${JOVE_TOOL_FLAGS}
    ${arch_extra_cflags}
  )

  if (JOVE_HAVE_MEMFD)
    target_compile_definitions(jove-${arch} PRIVATE JOVE_HAVE_MEMFD)
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

set(qemu_build_dir_name "${JOVE_QEMU_BUILD_DIR_NAME}")

# FIXME (hack)
if(LLVM_USE_SANITIZER)
  string(APPEND qemu_build_dir_name "_asan")
endif()

foreach(arch ${JOVE_TARGETS_TO_BUILD})
  tool_for_arch("${arch}" "${JOVE_${arch}_extra_cflags}" "${JOVE_SRC_DIR}/qemu/${qemu_build_dir_name}")
endforeach()
