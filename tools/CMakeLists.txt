set(JOVE_VERSION "v0.8")

set(JOVE_TOOL_FLAGS
  "-fwrapv"
  "-Wno-initializer-overrides"
  "-Wno-c99-designator"
  "-Wno-deprecated-declarations"
  "-Wno-cast-qual"
  "-Wno-bitwise-instead-of-logical"
  "-Wno-sign-compare"
  "-DBOOST_ICL_USE_STATIC_BOUNDED_INTERVALS"
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

function(tool_for_arch arch arch_extra_cflags qemu_objs)
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
    ../core/tcg.cpp
    ../core/tool.cpp
    ../core/triple.cpp
    ../core/util.cpp
    ../core/vdso.cpp
    check-helper.cpp
    gen-tcgconstants.cpp
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
    ${qemu_objs}

    -Wl,--whole-archive
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libhwcore.fa
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqom.fa
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libevent-loop-base.a
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/gdbstub/libgdb_user.fa
    -Wl,--no-whole-archive
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemuutil.a
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/tcg/libtcg_user.fa
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libhwcore.fa
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqom.fa
    ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/gdbstub/libgdb_user.fa
    ffi
    boost_system
    boost_filesystem
    boost_serialization
    glib-2.0
    atomic
  )

  target_include_directories(jove-${arch} PRIVATE
    ${JOVE_SRC_DIR}/lib/arch/${arch}
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

set(JOVE_x86_64_qemu_objs
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_cpu-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_machine-smp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/gdbstub_syscalls.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/cpus-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/page-vary-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_disas.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/accel_accel-user.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall.S.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall-error.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_user_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_user_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_x86_64_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_x86_64_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_xsave_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_cpu-dump.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_kvm_kvm-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_bpt_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_cc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_fpu_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_int_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_mem_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_misc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_mpx_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_tcg-cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/linux-user_uname.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-x86_64-linux-user.fa.p/meson-generated_.._x86_64-linux-user-gdbstub-xml.c.o
)

set(JOVE_i386_qemu_objs
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_cpu-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_machine-smp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/gdbstub_syscalls.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/cpus-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/page-vary-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_disas.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/accel_accel-user.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall.S.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall-error.c.o

  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_user_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_user_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_i386_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_i386_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_xsave_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_cpu-dump.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_kvm_kvm-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_bpt_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_cc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_fpu_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_int_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_mem_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_misc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_mpx_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_tcg-cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/target_i386_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_uname.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/linux-user_vm86.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-i386-linux-user.fa.p/meson-generated_.._i386-linux-user-gdbstub-xml.c.o
)

set(JOVE_mipsel_qemu_objs
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_cpu-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_machine-smp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/gdbstub_syscalls.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/cpus-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/page-vary-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_mips.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_nanomips.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_disas.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/accel_accel-user.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall.S.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall-error.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_mips_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_mips_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_fpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_msa.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_dsp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_exception.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_fpu_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_ldst_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_lmmi_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_msa_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_msa_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_op_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_rel6_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_translate_addr_const.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_txx9_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_vr54xx_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_vr54xx_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/target_mips_tcg_mxu_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mipsel-linux-user.fa.p/linux-user_uname.c.o
)

set(JOVE_mips_qemu_objs
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_cpu-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_machine-smp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/gdbstub_syscalls.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/cpus-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/page-vary-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_mips.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_nanomips.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_disas.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/accel_accel-user.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall.S.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall-error.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_mips_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_mips_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_fpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_msa.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_dsp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_exception.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_fpu_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_ldst_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_lmmi_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_msa_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_msa_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_op_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_rel6_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_translate_addr_const.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_txx9_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_vr54xx_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_vr54xx_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/target_mips_tcg_mxu_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips-linux-user.fa.p/linux-user_uname.c.o
)

set(JOVE_mips64el_qemu_objs
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_cpu-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_machine-smp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/gdbstub_syscalls.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/cpus-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/page-vary-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_mips.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_nanomips.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_disas.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/accel_accel-user.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall.S.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall-error.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_mips64_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_mips64_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_fpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_msa.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_dsp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_exception.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_fpu_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_ldst_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_lmmi_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_msa_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_msa_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_op_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_rel6_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_translate_addr_const.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_txx9_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_vr54xx_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_vr54xx_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_tx79_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/target_mips_tcg_octeon_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-mips64el-linux-user.fa.p/linux-user_uname.c.o
)

set(JOVE_aarch64_qemu_objs
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_cpu-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/hw_core_machine-smp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/gdbstub_syscalls.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/cpus-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/page-vary-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/disas_disas.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/accel_accel-user.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall.S.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libcommon.fa.p/common-user_safe-syscall-error.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_aarch64_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_aarch64_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_debug_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_vfp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_kvm-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_cpu64.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_gdbstub64.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_cpu32.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate-m-nocp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate-mve.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate-neon.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate-vfp.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_crypto_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_hflags.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_iwmmxt_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_m_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_mve_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_neon_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_op_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_tlb_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_vec_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_cpu64.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate-a64.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate-sve.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_translate-sme.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_helper-a64.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_mte_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_pauth_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_sme_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/target_arm_tcg_sve_helper.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/semihosting_guestfd.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/semihosting_syscalls.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/semihosting_arm-compat-semi.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_uname.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_flatload.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/linux-user_semihost.c.o
  ${JOVE_SRC_DIR}/qemu/${JOVE_QEMU_BUILD_DIR_NAME}/libqemu-aarch64-linux-user.fa.p/meson-generated_.._aarch64-linux-user-gdbstub-xml.c.o
)

foreach(arch ${JOVE_TARGETS_TO_BUILD})
  tool_for_arch("${arch}" "${JOVE_${arch}_extra_cflags}" "${JOVE_${arch}_qemu_objs}")
endforeach()
