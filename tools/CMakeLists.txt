set(JOVE_VERSION "v0.8")

set(JOVE_TOOL_FLAGS
  "-fwrapv"
  "-Wno-initializer-overrides"
  "-Wno-c99-designator"
  "-DBOOST_ICL_USE_STATIC_BOUNDED_INTERVALS"
)

set(JOVE_ALL_TARGETS
  i386
  x86_64
  aarch64
  mipsel
  mips
  mips64
)

set(JOVE_TARGETS_TO_BUILD "all"
    CACHE STRING "Semicolon-separated list of targets to build, or \"all\".")

if( JOVE_TARGETS_TO_BUILD STREQUAL "all" )
  set( JOVE_TARGETS_TO_BUILD ${JOVE_ALL_TARGETS} )
endif()

function(tool_for_arch arch arch_extra_cflags)
  string(TOUPPER "${arch}" uc_arch)

  add_llvm_tool(jove-${arch}
    ../core/crypto.cpp
    ../core/disas.cpp
    ../core/elf.cpp
    ../core/explore.cpp
    ../core/fd.cpp
    ../core/ida.cpp
    ../core/jv.cpp
    ../core/locator.cpp
    ../core/process.cpp
    ../core/recovery.cpp
    ../core/score.cpp
    ../core/symbolizer.cpp
    ../core/tool.cpp
    ../core/triple.cpp
    ../core/util.cpp
    ../core/vdso.cpp
    check-helper.cpp
    jove-add.cpp
    jove-analyze.cpp
    jove-bootstrap.cpp
    jove-cfg.cpp
    jove-decompile.cpp
    jove-dig.cpp
    jove-dump.cpp
    jove-extract.cpp
    jove-ida.cpp
    jove-init.cpp
    jove-invalidate.cpp
    jove-llvm.cpp
    jove-loop.cpp
    jove-readtrace.cpp
    jove-recompile.cpp
    jove-recover.cpp
    jove-run.cpp
    jove-score.cpp
    jove-server.cpp
    jove-stub.cpp
    jove-trace.cpp
    jove-trace2addrs.cpp
    jove-trace2asm.cpp
    jove-trace2lines.cpp
    jove-unstub.cpp
    jv2xml.cpp
    tcgdump.cpp
  )

  target_link_libraries(jove-${arch} PRIVATE
    boost_system
    boost_filesystem
    boost_serialization
    ssl
    crypto
    glib-2.0
  )

  target_include_directories(jove-${arch} PRIVATE
    ../lib/arch/${arch}
  )

  target_compile_options(jove-${arch} PRIVATE
    -DTARGET_${uc_arch}
    -DTARGET_ARCH_NAME=\"${arch}\"
    -DJOVE_VERSION=\"${JOVE_VERSION}\"
    ${JOVE_TOOL_FLAGS}
    ${arch_extra_cflags}
  )

endfunction()

#
# Insist on C++ 17 features.
#
set(CMAKE_CXX_STANDARD 17)
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

foreach(arch ${JOVE_TARGETS_TO_BUILD})
  tool_for_arch("${arch}" "${JOVE_${arch}_extra_cflags}")
endforeach()
