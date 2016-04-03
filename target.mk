include config.mk

libqemutcg_all: $(build_dir)/obj2llvmdump-$(_TARGET_NAME) $(build_dir)/tcgglobals-$(_TARGET_NAME) $(build_dir)/libqemutcg-$(_TARGET_NAME).bc $(build_dir)/runtime-helpers-$(_TARGET_NAME).bc

_QEMU_TARGET := $(_TARGET_NAME)-linux-user

include $(qemu_build_dir)/$(_QEMU_TARGET)/Makefile

_INCLUDES := -I$(qemu_build_dir) -I$(qemu_build_dir)/$(_QEMU_TARGET) -I$(SRC_PATH)/target-$(TARGET_BASE_ARCH) $(QEMU_INCLUDES)
_CFLAGS   := $(CFLAGS) $(QEMU_CFLAGS) -DNEED_CPU_H
_CXXFLAGS := $(CXXFLAGS) $(QEMU_CXXFLAGS) -DNEED_CPU_H

ifeq ($(_TARGET_NAME),x86_64)
llvm_arch = x86
endif
ifeq ($(_TARGET_NAME),i386)
llvm_arch = x86
endif
ifeq ($(_TARGET_NAME),arm)
llvm_arch = arm
endif
ifeq ($(_TARGET_NAME),aarch64)
llvm_arch = aarch64
endif
ifeq ($(_TARGET_NAME),mipsel)
llvm_arch = mips
endif

#
# obj2llvmdump
#

$(build_dir)/obj2llvmdump-$(_TARGET_NAME): $(build_dir)/obj2llvmdump-$(_TARGET_NAME).2.bc
	@echo CLANG++ $(notdir $@ $^)
	$(llvm_dir)/bin/clang++ -o $@ $< -O3 -flto -fPIC $(shell $(llvm_dir)/bin/llvm-config --libs object $(llvm_arch)) $(shell $(llvm_dir)/bin/llvm-config --ldflags) -lglib-2.0 -pthread -lcurses -lz -L $(boost_dir)/lib -lboost_system -lboost_program_options

$(build_dir)/obj2llvmdump-$(_TARGET_NAME).2.bc: $(build_dir)/obj2llvmdump-$(_TARGET_NAME).1.bc
	@echo OPT $(notdir $@ $^)
	@$(llvm_dir)/bin/opt -o $@ -globaldce $<

$(build_dir)/obj2llvmdump-$(_TARGET_NAME).1.bc: $(build_dir)/obj2llvmdump-$(_TARGET_NAME).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --only-external-regex 'main'

$(build_dir)/obj2llvmdump-$(_TARGET_NAME).0.bc: $(build_dir)/qemu-$(_TARGET_NAME).bc $(build_dir)/qemutcg-$(_TARGET_NAME).bc $(build_dir)/obj2llvmdump-$(_TARGET_NAME).bc $(build_dir)/obj2llvmdump_c-$(_TARGET_NAME).bc $(build_dir)/mc-$(_TARGET_NAME).bc
	@echo BCLINK $(notdir $@ $^)
	@$(llvm_dir)/bin/llvm-link -o $@ $^

$(build_dir)/obj2llvmdump_c-$(_TARGET_NAME).bc: $(build_dir)/obj2llvmdump_c.c
	@echo CLANG $(notdir $@ $^)
	@$(llvm_dir)/bin/clang -o $@ -c -emit-llvm -I $(include_dir) -Wall -g -O0 $(_INCLUDES) $(filter-out -fno-inline,$(_CFLAGS)) $<

$(build_dir)/obj2llvmdump-$(_TARGET_NAME).bc: $(build_dir)/obj2llvmdump.cpp
	@echo CLANG++ $(notdir $@ $^)
	@$(llvm_dir)/bin/clang++ -o $@ -c -emit-llvm -I $(include_dir) -Wall -g -O0 -fno-inline $(_INCLUDES) $(filter-out -fno-inline,$(_CXXFLAGS)) $(filter-out -fno-exceptions,$(shell $(llvm_dir)/bin/llvm-config --cxxflags)) $<

#
# mc
#
$(build_dir)/mc-$(_TARGET_NAME).bc: $(build_dir)/mc.cpp
	@echo CLANG++ $(notdir $@ $^)
	@$(llvm_dir)/bin/clang++ -o $@ -c -emit-llvm -I $(include_dir) -Wall -g -O0 -fno-inline $(_INCLUDES) $(filter-out -fno-inline,$(_CXXFLAGS)) $(filter-out -fno-exceptions,$(shell $(llvm_dir)/bin/llvm-config --cxxflags)) $<


#
# tcgglobals
#

$(build_dir)/tcgglobals-$(_TARGET_NAME): $(build_dir)/tcgglobals-$(_TARGET_NAME).2.bc
	@echo CLANG $(notdir $@ $^)
	@$(llvm_dir)/bin/clang -o $@ $< -flto -fPIC -lglib-2.0 -pthread

$(build_dir)/tcgglobals-$(_TARGET_NAME).2.bc: $(build_dir)/tcgglobals-$(_TARGET_NAME).1.bc
	@echo OPT $(notdir $@ $^)
	@$(llvm_dir)/bin/opt -o $@ -globaldce $<

$(build_dir)/tcgglobals-$(_TARGET_NAME).1.bc: $(build_dir)/tcgglobals-$(_TARGET_NAME).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --only-external-regex 'main'

$(build_dir)/tcgglobals-$(_TARGET_NAME).0.bc: $(build_dir)/qemu-$(_TARGET_NAME).bc $(build_dir)/qemutcg-$(_TARGET_NAME).bc $(build_dir)/tcgglobals-$(_TARGET_NAME).bc
	@echo BCLINK $(notdir $@ $^)
	@$(llvm_dir)/bin/llvm-link -o $@ $^

$(build_dir)/tcgglobals-$(_TARGET_NAME).bc: $(build_dir)/tcgglobals.c
	@echo CLANG $(notdir $@ $^)
	$(llvm_dir)/bin/clang -o $@ -c -emit-llvm -I $(include_dir) -Wall -O3 $(_INCLUDES) $(filter-out -fno-inline,$(_CFLAGS)) $<

#
# library
#

$(build_dir)/libqemutcg-$(_TARGET_NAME).bc: $(build_dir)/libqemutcg-$(_TARGET_NAME).1.bc
	@echo OPT $(notdir $@ $^)
	@$(llvm_dir)/bin/opt -o $@ -globaldce $<

$(build_dir)/libqemutcg-$(_TARGET_NAME).1.bc: $(build_dir)/libqemutcg-$(_TARGET_NAME).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --only-external-regex 'libqemutcg_.*'

$(build_dir)/libqemutcg-$(_TARGET_NAME).0.bc: $(build_dir)/qemu-$(_TARGET_NAME).bc $(build_dir)/qemutcg-$(_TARGET_NAME).bc
	@echo BCLINK $(notdir $@ $^)
	@$(llvm_dir)/bin/llvm-link -o $@ $^

#
# library C API
#

$(build_dir)/qemutcg-$(_TARGET_NAME).bc: $(build_dir)/translate-ldst-helpers-$(_TARGET_NAME).bc $(build_dir)/qemutcg-$(_TARGET_NAME).0.bc
	@echo BCLINK $(notdir $@ $^)
	@$(llvm_dir)/bin/llvm-link -o $@ $^

$(build_dir)/translate-ldst-helpers-$(_TARGET_NAME).bc: $(build_dir)/translate_ldst_helpers.c
	@echo CLANG $(notdir $@ $^)
	@$(llvm_dir)/bin/clang -o $@ -c -emit-llvm -I $(include_dir) -Wall -g -O0 -fno-inline $(_INCLUDES) $(filter-out -fno-inline,$(_CFLAGS)) $<

$(build_dir)/qemutcg-$(_TARGET_NAME).0.bc: $(build_dir)/qemutcg.c
	@echo CLANG $(notdir $@ $^)
	@$(llvm_dir)/bin/clang -o $@ -c -emit-llvm -I $(include_dir) -Wall -g -O0 -fno-inline $(_INCLUDES) $(filter-out -fno-inline,$(_CFLAGS)) $<

#
# library base QEMU bitcode
#

$(build_dir)/qemu-$(_TARGET_NAME).bc: $(build_dir)/qemu-$(_TARGET_NAME).7.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --change-fn-def-to-decl-regex 'main'

$(build_dir)/qemu-$(_TARGET_NAME).7.bc: $(build_dir)/qemu-$(_TARGET_NAME).6.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --make-fn-into-stub-regex '\(helper_.*\)\|\(do_interrupt.*\)\|\(load_segment_ra\)\|\(get_rsp_from_tss\)\|\(qemu_system_reset_request\)\|\(switch_tss_ra\)\|\(gen_tb_start\)\|\(gen_tb_end\)'

#
# runtime helpers
#

$(build_dir)/runtime-helpers-$(_TARGET_NAME).bc: $(build_dir)/runtime-helpers-$(_TARGET_NAME).3.bc
	@echo OPT $(notdir $@ $^)
	@$(llvm_dir)/bin/opt -o $@ -O3 -strip-debug -disable-loop-vectorization -disable-slp-vectorization -scalarizer -memdep-enable-load-widening=false $<

$(build_dir)/runtime-helpers-$(_TARGET_NAME).3.bc: $(build_dir)/runtime-helpers-$(_TARGET_NAME).2.bc
	@echo KNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --remove-noinline-attr-regex '.*'

$(build_dir)/runtime-helpers-$(_TARGET_NAME).2.bc: $(build_dir)/runtime-helpers-$(_TARGET_NAME).1.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --change-fn-def-to-decl-regex '\(helper_.*mmu\)\|\(raise_interrupt.*\)'

$(build_dir)/runtime-helpers-$(_TARGET_NAME).1.bc: $(build_dir)/runtime-helpers-$(_TARGET_NAME).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --only-external-regex 'helper_.*'

$(build_dir)/runtime-helpers-$(_TARGET_NAME).0.bc: $(build_dir)/qemu-$(_TARGET_NAME).6.bc $(build_dir)/runtime_ldst_helpers-$(_TARGET_NAME).bc
	@echo BCLINK $(notdir $@ $^)
	@$(llvm_dir)/bin/llvm-link -o $@ $^

$(build_dir)/runtime_ldst_helpers-$(_TARGET_NAME).bc: $(build_dir)/runtime_ldst_helpers.c
	@echo CLANG $(notdir $@ $^)
	@$(llvm_dir)/bin/clang -o $@ -c -emit-llvm -Wall -O3 -I $(include_dir) $(_INCLUDES) $(filter-out -fno-inline,$(_CFLAGS)) $<

#
# process QEMU bitcode
#

$(build_dir)/qemu-$(_TARGET_NAME).6.bc: $(build_dir)/qemu-$(_TARGET_NAME).5.bc
	@echo OPT $(notdir $@ $^)
	@$(llvm_dir)/bin/opt -o $@ -O3 -disable-loop-vectorization -disable-slp-vectorization -scalarizer -memdep-enable-load-widening=false $<

$(build_dir)/qemu-$(_TARGET_NAME).5.bc: $(build_dir)/qemu-$(_TARGET_NAME).4.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --set-global-constant-regex 'qemu_loglevel.*'

$(build_dir)/qemu-$(_TARGET_NAME).4.bc: $(build_dir)/qemu-$(_TARGET_NAME).3.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --remove-noinline-attr-regex '\(.*qemu_loglevel.*\)\|\(bswap.*\)\|\(lshift.*\)'

$(build_dir)/qemu-$(_TARGET_NAME).3.bc: $(build_dir)/qemu-$(_TARGET_NAME).2.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --delete-global-ctors

$(build_dir)/qemu-$(_TARGET_NAME).2.bc: $(build_dir)/qemu-$(_TARGET_NAME).1.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --make-external-regex '\(cond_name\)\|\(ldst_name\)\|\(tcg_find_helper\)\|\(tcg_get_arg_str_idx\)\|\(do_qemu_init_mips_cpu_register_types\)\|\(do_qemu_init_aarch64_cpu_register_types\)\|\(do_qemu_init_arm_cpu_register_types\)\|\(do_qemu_init_container_register_types\)\|\(do_qemu_init_cpu_register_types\)\|\(do_qemu_init_fw_path_provider_register_types\)\|\(do_qemu_init_hotplug_handler_register_types\)\|\(do_qemu_init_irq_register_types\)\|\(do_qemu_init_nmi_register_types\)\|\(do_qemu_init_qdev_register_types\)\|\(do_qemu_init_x86_cpu_register_types\)\|\(init_get_clock\)\|\(object_do_qemu_init_register_types\)\|\(object_interfaces_do_qemu_init_register_types\)\|\(qemu_thread_atexit_init\)\|\(rcu_init\)'

$(build_dir)/qemu-$(_TARGET_NAME).1.bc: $(build_dir)/qemu-$(_TARGET_NAME).0.bc
	@echo LLKNIFE $(notdir $@ $^)
	@$(build_dir)/llknife -o $@ -i $< --make-fn-into-stub-regex '\(print_insn_arm_a64\)\|\(print_insn_thumb1\)\|\(print_insn_arm\)\|\(helper_set_dr\)\|\(helper_iret.*\)\|\(helper_lcall_.*\)\|\(helper_lret.*\)\|\(helper_lldt\)\|\(helper_hlt\)\|\(helper_pause\)\|\(helper_lock\)\|\(helper_lock_init\)\|\(helper_unlock\)\|\(helper_ltr\)\|\(helper_debug\)\|\(helper_mwait\)\|\(helper_sysret\)\|\(helper_verw\)\|\(helper_lar\)\|\(helper_verr\)\|\(helper_lsl\)\|\(helper_load_seg\)\|\(helper_sysenter\)\|\(helper_syscall\)\|\(helper_cpuid\)\|\(helper_sysexit\)\|\(helper_check_io[bwl]\)\|\(helper_out[bwl]\)\|\(helper_in[bwl]\)\|\(helper_vm.*\)\|\(vm_stop\)\|\(pause_all_vcpus\)\|\(qemu_system_suspend_request\)\|\(helper_ljmp_protected\)\|\(x86_st.*_phys\)\|\(x86_ld.*_phys\)\|\(address_space_.*\)\|\(raise_exception.*\)\|\(raise_interrupt.*\)\|\(helper_raise_interrupt\)\|\(helper_wfi\)\|\(helper_cpsr_write\)\|\(helper_.*_msr\)\|\(helper.*_mrs\)\|\(helper_exception_return\)'

$(build_dir)/qemu-$(_TARGET_NAME).0.bc:
	@echo BCLINK $(notdir $@ $^ qemustub.bc qemuutil.bc)
	@$(llvm_dir)/bin/llvm-link -o $@ $(sort $(patsubst %,$(qemu_build_dir)/$(_QEMU_TARGET)/%,$(all-obj-y))) -override $(build_dir)/qemustub.bc -override $(build_dir)/qemuutil.bc
