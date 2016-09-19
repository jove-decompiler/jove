include config.mk

targ_build_dir := $(build_dir)/$(_TARGET_NAME)
res = $(targ_build_dir)/$(1)
tool = _jove_$(1)

jove_all: $(call res,jove-init) $(call res,jove-recompile) $(call res,thunk).bc

_QEMU_TARGET := $(_TARGET_NAME)-linux-user

include $(qemu_build_dir)/$(_QEMU_TARGET)/Makefile

LLCONFIG := $(llvm_dir)/bin/llvm-config
LLCXX    := $(llvm_dir)/bin/clang++
LLCC     := $(llvm_dir)/bin/clang
LLOPT    := $(llvm_dir)/bin/opt
LLKNIFE  := $(build_dir)/llknife
LLLD     := $(llvm_dir)/bin/llvm-link

_INCLUDES := -I$(build_dir)/$(_TARGET_NAME) \
             -I$(include_dir) \
             -I$(build_dir) \
             -I$(qemu_build_dir) \
             -I$(qemu_build_dir)/$(_QEMU_TARGET) \
             -I$(SRC_PATH)/target-$(TARGET_BASE_ARCH) \
             $(QEMU_INCLUDES)

_CFLAGS   := $(CFLAGS) \
             $(QEMU_CFLAGS) \
             -DNEED_CPU_H \
             $(shell pkg-config --cflags glib-2.0)

_CXXFLAGS := $(shell $(LLCONFIG) --cxxflags) \
             $(CXXFLAGS) $(QEMU_CXXFLAGS) \
             -DNEED_CPU_H \
			 -Wno-c99-extensions \
			 -Wno-dollar-in-identifier-extension \
             $(shell pkg-config --cflags glib-2.0)

_CFLAGS   := $(filter-out -fstack-protector-strong,$(filter-out -DNDEBUG,$(filter-out -DPIE,$(filter-out -fPIE,$(filter-out -g,$(filter-out -flto,$(filter-out -fno-inline,$(_CFLAGS))))))))
_CXXFLAGS := $(filter-out -fstack-protector-strong,$(filter-out -DNDEBUG,$(filter-out -Wno-maybe-uninitialized,$(filter-out -flto,$(filter-out -fno-exceptions,$(filter-out -fno-inline,$(_CXXFLAGS)))))))

#
# jove-recompile
#

$(call tool,recompile)_SRC_NMS = jove_recompile.cpp \
                                 elf_recompiler.cpp \
                                 coff_recompiler.cpp \
                                 recompiler.cpp

$(call tool,recompile)_SRCS := $(patsubst %,$(build_dir)/%,$($(call tool,recompile)_SRC_NMS))
$(call tool,recompile)_OBJS := $(patsubst %.cpp,$(call res,%).o,$($(call tool,recompile)_SRC_NMS))
$(call tool,recompile)_DEPS := $(patsubst %.cpp,$(call res,%).d,$($(call tool,recompile)_SRC_NMS))

$(call res,jove-recompile): $($(call tool,recompile)_OBJS)
	@echo CLANG++ $(notdir $@ $^)
	@$(LLCXX) -o $@ \
	  $(_CXXFLAGS) $($(call tool,recompile)_OBJS) \
	  -Wl,-rpath,$(llvm_dir)/lib $(llvm_dir)/lib/libLLVM.so \
	  $(shell $(LLCONFIG) --ldflags) \
	  -lglib-2.0 \
	  -pthread \
	  -lcurses \
	  -lz \
	  -lboost_system \
	  -lboost_program_options \
	  -lboost_filesystem \
	  -ldl

-include $($(call tool,recompile)_DEPS)

#
# jove-init
#

$(call tool,init)_SRC_NMS = jove_init.cpp \
                            mc.cpp \
                            elf_binary.cpp \
                            coff_binary.cpp \
                            translator.cpp

$(call tool,init)_SRCS := $(patsubst %,$(build_dir)/%,$($(call tool,init)_SRC_NMS))
$(call tool,init)_OBJS := $(patsubst %.cpp,$(call res,%).o,$($(call tool,init)_SRC_NMS))
$(call tool,init)_DEPS := $(patsubst %.cpp,$(call res,%).d,$($(call tool,init)_SRC_NMS))

$(call res,jove-init): $($(call tool,init)_OBJS) $(call res,libqemutcg).so
	@echo CLANG++ $(notdir $@ $^)
	@$(LLCXX) -o $@ \
	  $(_CXXFLAGS) $($(call tool,init)_OBJS) \
	  -Wl,-rpath,$(llvm_dir)/lib $(llvm_dir)/lib/libLLVM.so \
	  -Wl,-rpath,$(targ_build_dir) $(call res,libqemutcg).so \
	  $(shell $(LLCONFIG) --ldflags) \
	  -lglib-2.0 \
	  -pthread \
	  -lcurses \
	  -lz \
	  -lboost_system \
	  -lboost_program_options \
	  -lboost_filesystem \
	  -ldl

-include $($(call tool,init)_DEPS)

#
# rules
#

$(call res,%).o: $(build_dir)/%.cpp
	@echo CLANG++ $(notdir $@ $<)
	@$(LLCXX) -o $@ -c -MMD -Wall -g $(_INCLUDES) $(_CXXFLAGS) -O1 $<

#
# extra dependencies
#
$(call res,recompiler).o: $(call res,helpers).cpp $(call res,thunk).cpp
$(call res,jove_recompile).o: $(call res,helpers).cpp $(call res,thunk).cpp
$(call res,jove_init).o: $(call res,tcgdefs).hpp $(call res,abi_callingconv).hpp
$(call res,translator).o: $(call res,abi_callingconv_arg_regs).cpp $(call res,abi_callingconv_ret_regs).cpp $(call res,helpers).cpp $(call res,tcg_globals).cpp $(call res,tcgdefs).hpp $(call res,abi_callingconv).hpp

#
# jove-recompile
#

$(call res,thunk).bc: $(build_dir)/thunk_$(_TARGET_NAME).c
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -c -emit-llvm -fPIC -Wall -O2 $(_INCLUDES) $(_CFLAGS) $<

$(call res,thunk).cpp: $(call res,thunk).bc
	@echo XXD -include $(notdir $@ $^)
	@xxd -include < $< > $@

#
# output of ABI calling conventions
#
$(call res,abi_callingconv).hpp: $(call res,abi_callingconv)
	@echo ABICALLINGCONV $(notdir $@)
	@$(call res,abi_callingconv) 1 $(build_dir)/$(_TARGET_NAME).callconv > $@

$(call res,abi_callingconv_arg_regs).cpp: $(call res,abi_callingconv)
	@echo ABICALLINGCONV $(notdir $@)
	@$(call res,abi_callingconv) 2 $(build_dir)/$(_TARGET_NAME).callconv > $@

$(call res,abi_callingconv_ret_regs).cpp: $(call res,abi_callingconv)
	@echo ABICALLINGCONV $(notdir $@)
	@$(call res,abi_callingconv) 3 $(build_dir)/$(_TARGET_NAME).callconv > $@


#
# ABI calling convention
#
$(call res,abi_callingconv): $(call res,abi_callingconv).1.bc
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -O3 -g $< -fPIC -lglib-2.0 -pthread

$(call res,abi_callingconv).1.bc: $(call res,abi_callingconv).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --only-external-regex 'main'

$(call res,abi_callingconv).0.bc: $(call res,qemu).bc $(call res,qemutcg).bc $(call res,abi_callingconv).bc
	@echo BCLINK $(notdir $@ $^)
	@$(LLLD) -o $@ $^

$(call res,abi_callingconv).bc: $(build_dir)/abi_callingconv.c
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -c -emit-llvm -Wall -O3 $(_INCLUDES) $(_CFLAGS) $<

#
# output of tcgdefs
#
$(call res,tcg_globals).cpp: $(call res,tcgdefs)
	@echo TCGDEFS $(notdir $@ $^)
	@$(call res,tcgdefs) gblsdef > $@

$(call res,tcgdefs).hpp: $(call res,tcgdefs)
	@echo TCGDEFS $(notdir $@ $^)
	@$(call res,tcgdefs) > $@

#
# tcgdefs
#
$(call res,tcgdefs): $(call res,tcgdefs).1.bc
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -O3 -g $< -fPIC -lglib-2.0 -pthread

$(call res,tcgdefs).1.bc: $(call res,tcgdefs).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --only-external-regex 'main'

$(call res,tcgdefs).0.bc: $(call res,qemu).bc $(call res,qemutcg).bc $(call res,tcgdefs).bc
	@echo BCLINK $(notdir $@ $^)
	@$(LLLD) -o $@ $^

$(call res,tcgdefs).bc: $(build_dir)/tcgdefs.c
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -c -emit-llvm -Wall -O3 $(_INCLUDES) $(_CFLAGS) $<

#
# tcgglobals
#

$(call res,tcgglobals): $(call res,tcgglobals).1.bc
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -O3 $< -fPIC -lglib-2.0 -pthread

$(call res,tcgglobals).1.bc: $(call res,tcgglobals).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --only-external-regex 'main'

$(call res,tcgglobals).0.bc: $(call res,qemu).bc $(call res,qemutcg).bc $(call res,tcgglobals).bc
	@echo BCLINK $(notdir $@ $^)
	@$(LLLD) -o $@ $^

$(call res,tcgglobals).bc: $(build_dir)/tcgglobals.c
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -c -emit-llvm -Wall -g -O2 $(_INCLUDES) $(_CFLAGS) $<

#
# C library implementing API to QEMU translation layer
#
$(call res,libqemutcg).so: $(call res,libqemutcg).2.bc
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -shared -fPIC -g -O0 $< -lglib-2.0 -pthread

$(call res,libqemutcg).2.bc: $(call res,libqemutcg).1.bc
	@echo OPT $(notdir $@ $^)
	@$(LLOPT) -o $@ -globaldce $<

$(call res,libqemutcg).1.bc: $(call res,libqemutcg).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --only-external-regex 'libqemutcg_.*'

$(call res,libqemutcg).0.bc: $(call res,qemu).bc $(call res,qemutcg).bc
	@echo BCLINK $(notdir $@ $^)
	@$(LLLD) -o $@ $^

#
# C API to QEMU translation layer bitcode
#
$(call res,qemutcg).bc: $(call res,translate-ldst-helpers).bc $(call res,qemutcg).0.bc
	@echo BCLINK $(notdir $@ $^)
	@$(LLLD) -o $@ $^

$(call res,translate-ldst-helpers).bc: $(build_dir)/translate_ldst_helpers.c
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -c -emit-llvm -Wall -g -O2 $(_INCLUDES) $(_CFLAGS) $<

$(call res,qemutcg).0.bc: $(build_dir)/qemutcg.c
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -c -emit-llvm -Wall -g -O0 $(_INCLUDES) $(_CFLAGS) $<

#
# library base QEMU bitcode
#
$(call res,qemu).bc: $(call res,qemu).7.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --change-fn-def-to-decl-regex 'main'

$(call res,qemu).7.bc: $(call res,qemu).6.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --make-fn-into-stub-regex '\(helper_.*\)\|\(do_interrupt.*\)\|\(load_segment_ra\)\|\(get_rsp_from_tss\)\|\(qemu_system_reset_request\)\|\(switch_tss_ra\)\|\(gen_tb_start\)\|\(gen_tb_end\)'

#
# helpers
#
$(call res,helpers).cpp: $(call res,helpers).bc
	@echo XXD -include $(notdir $@ $^)
	@xxd -include < $< > $@

$(call res,helpers).bc: $(call res,helpers).5.bc
	@echo OPT $(notdir $@ $^)
	@$(LLOPT) -o $@ -O3 -strip-debug -disable-loop-vectorization -disable-slp-vectorization -scalarizer $<

$(call res,helpers).5.bc: $(call res,helpers).4.bc $(build_dir)/transform-helpers $(call res,tcgglobals)
	@echo TRANSFORMHELPERS $(notdir $@ $<)
	$(build_dir)/transform-helpers -o $@ -i $< --arch $(_TARGET_NAME) $$($(call res,tcgglobals) | xargs)

$(call res,helpers).4.bc: $(call res,helpers).3.bc
	@echo OPT $(notdir $@ $^)
	@$(LLOPT) -o $@ -O3 -strip-debug -disable-loop-vectorization -disable-slp-vectorization -scalarizer $<

$(call res,helpers).3.bc: $(call res,helpers).2.bc
	@echo KNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --remove-noinline-attr-regex '.*'

$(call res,helpers).2.bc: $(call res,helpers).1.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --change-fn-def-to-decl-regex '\(helper_.*mmu\)\|\(raise_interrupt.*\)'

$(call res,helpers).1.bc: $(call res,helpers).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --only-external-regex 'helper_.*'

$(call res,helpers).0.bc: $(call res,qemu).6.bc $(call res,ldst_helpers).bc
	@echo BCLINK $(notdir $@ $^)
	@$(LLLD) -o $@ $^

$(call res,ldst_helpers).bc: $(build_dir)/ldst_helpers.c
	@echo CLANG $(notdir $@ $^)
	@$(LLCC) -o $@ -c -emit-llvm -Wall -O3 $(_INCLUDES) $(_CFLAGS) $<

#
# process QEMU bitcode
#

$(call res,qemu).6.bc: $(call res,qemu).5.bc
	@echo OPT $(notdir $@ $^)
	@$(LLOPT) -o $@ -disable-loop-vectorization -disable-slp-vectorization -scalarizer  -globaldce $<

$(call res,qemu).5.bc: $(call res,qemu).4.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --set-global-constant-regex 'qemu_loglevel.*'

$(call res,qemu).4.bc: $(call res,qemu).3.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --remove-noinline-attr-regex '\(.*qemu_loglevel.*\)\|\(bswap.*\)\|\(lshift.*\)'

$(call res,qemu).3.bc: $(call res,qemu).2.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --delete-global-ctors

$(call res,qemu).2.bc: $(call res,qemu).1.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --make-external-regex '\(cond_name\)\|\(ldst_name\)\|\(tcg_find_helper\)\|\(tcg_get_arg_str_idx\)\|\(do_qemu_init_mips_cpu_register_types\)\|\(do_qemu_init_aarch64_cpu_register_types\)\|\(do_qemu_init_arm_cpu_register_types\)\|\(do_qemu_init_container_register_types\)\|\(do_qemu_init_cpu_register_types\)\|\(do_qemu_init_fw_path_provider_register_types\)\|\(do_qemu_init_hotplug_handler_register_types\)\|\(do_qemu_init_irq_register_types\)\|\(do_qemu_init_nmi_register_types\)\|\(do_qemu_init_qdev_register_types\)\|\(do_qemu_init_x86_cpu_register_types\)\|\(init_get_clock\)\|\(object_do_qemu_init_register_types\)\|\(object_interfaces_do_qemu_init_register_types\)\|\(qemu_thread_atexit_init\)\|\(rcu_init\)'

$(call res,qemu).1.bc: $(call res,qemu).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(LLKNIFE) -o $@ -i $< --make-fn-into-stub-regex '\(print_insn_arm_a64\)\|\(print_insn_thumb1\)\|\(print_insn_arm\)\|\(helper_set_dr\)\|\(helper_iret.*\)\|\(helper_lcall_.*\)\|\(helper_lret.*\)\|\(helper_lldt\)\|\(helper_hlt\)\|\(helper_pause\)\|\(helper_lock\)\|\(helper_lock_init\)\|\(helper_unlock\)\|\(helper_ltr\)\|\(helper_debug\)\|\(helper_mwait\)\|\(helper_sysret\)\|\(helper_verw\)\|\(helper_lar\)\|\(helper_verr\)\|\(helper_lsl\)\|\(helper_load_seg\)\|\(helper_sysenter\)\|\(helper_syscall\)\|\(helper_cpuid\)\|\(helper_sysexit\)\|\(helper_check_io[bwl]\)\|\(helper_out[bwl]\)\|\(helper_in[bwl]\)\|\(helper_vm.*\)\|\(vm_stop\)\|\(pause_all_vcpus\)\|\(qemu_system_suspend_request\)\|\(helper_ljmp_protected\)\|\(x86_st.*_phys\)\|\(x86_ld.*_phys\)\|\(address_space_.*\)\|\(raise_exception.*\)\|\(raise_interrupt.*\)\|\(helper_raise_interrupt\)\|\(helper_wfi\)\|\(helper_cpsr_write\)\|\(helper_.*_msr\)\|\(helper.*_mrs\)\|\(helper_exception_return\)'

$(call res,qemu).0.bc:
	@echo BCLINK $(notdir $@ $^ qemustub.bc qemuutil.bc)
	@$(LLLD) -o $@ $(sort $(patsubst %,$(qemu_build_dir)/$(_QEMU_TARGET)/%,$(all-obj-y))) -override $(build_dir)/qemustub.bc -override $(build_dir)/qemuutil.bc
