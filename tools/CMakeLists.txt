set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  object
  passes
  objcarcopts
  coroutines
  symbolize
  )

# Insist on C++ 17 features.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D JOVE_VERSION=\\\"v0.77\\\"")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D TARGET_X86_64 -D TARGET_ARCH_NAME=\\\"x86_64\\\"")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fwrapv -Wno-initializer-overrides -Wno-c99-designator -D BOOST_ICL_USE_STATIC_BOUNDED_INTERVALS")

include_directories(../include)
include_directories(../lib)
include_directories(../core)
include_directories(../lib/arch/x86_64)

add_llvm_tool(jove
  ../core/crypto.cpp
  ../core/disas.cpp
  ../core/elf.cpp
  ../core/explore.cpp
  ../core/fd.cpp
  ../core/ida.cpp
  ../core/jv.cpp
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

target_link_libraries(jove PRIVATE
  boost_system
  boost_filesystem
  boost_serialization
  ssl
  crypto
  glib-2.0
)
