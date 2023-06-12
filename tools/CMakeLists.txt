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
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/hw_core_cpu-common.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/hw_core_machine-smp.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/gdbstub_syscalls.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/cpus-common.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/page-vary-common.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/disas_capstone.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/disas_disas.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/accel_accel-user.c.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/common-user_safe-syscall.S.o
    ${JOVE_SRC_DIR}/qemu/build/libcommon.fa.p/common-user_safe-syscall-error.c.o

    ${qemu_objs}

    -Wl,--whole-archive
    ${JOVE_SRC_DIR}/qemu/build/libhwcore.fa
    ${JOVE_SRC_DIR}/qemu/build/libqom.fa
    ${JOVE_SRC_DIR}/qemu/build/libevent-loop-base.a
    ${JOVE_SRC_DIR}/qemu/build/gdbstub/libgdb_user.fa
    -Wl,--no-whole-archive
    ${JOVE_SRC_DIR}/qemu/build/libqemuutil.a
    ${JOVE_SRC_DIR}/qemu/build/tcg/libtcg_user.fa
    ${JOVE_SRC_DIR}/qemu/build/libhwcore.fa
    ${JOVE_SRC_DIR}/qemu/build/libqom.fa
    ${JOVE_SRC_DIR}/qemu/build/gdbstub/libgdb_user.fa
    capstone
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

set(JOVE_x86_64_qemu_objs
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_user_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_user_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_x86_64_signal.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_x86_64_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_xsave_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_cpu-dump.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_kvm_kvm-stub.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_bpt_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_cc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_fpu_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_int_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_mem_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_misc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_mpx_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_tcg-cpu.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/linux-user_uname.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-x86_64-linux-user.fa.p/meson-generated_.._x86_64-linux-user-gdbstub-xml.c.o
)

set(JOVE_i386_qemu_objs
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_user_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_user_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_i386_signal.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_i386_cpu_loop.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_cpu.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_gdbstub.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_xsave_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_cpu-dump.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_kvm_kvm-stub.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_bpt_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_cc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_excp_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_fpu_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_int_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_mem_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_misc_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_mpx_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_seg_helper.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_tcg-cpu.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/target_i386_tcg_translate.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/trace_control-target.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/gdbstub_user-target.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/cpu.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/page-vary.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/fpu_softfloat.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_accel-common.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_accel-blocker.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_tcg-all.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_cpu-exec-common.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_cpu-exec.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_tb-maint.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_tcg-runtime-gvec.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_tcg-runtime.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_translate-all.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_translator.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_user-exec.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_user-exec-stub.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/accel_tcg_perf.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_elfload.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_exit.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_fd-trans.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_linuxload.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_main.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_mmap.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_signal.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_strace.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_syscall.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_thunk.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_uaccess.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_uname.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/linux-user_vm86.c.o
  ${JOVE_SRC_DIR}/qemu/build/libqemu-i386-linux-user.fa.p/meson-generated_.._i386-linux-user-gdbstub-xml.c.o
)

foreach(arch ${JOVE_TARGETS_TO_BUILD})
  tool_for_arch("${arch}" "${JOVE_${arch}_extra_cflags}" "${JOVE_${arch}_qemu_objs}")
endforeach()
