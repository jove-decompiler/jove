include config.mk

libqemutcg_all: $(build_dir)/libqemutcg-$(_TARGET_NAME).bc $(build_dir)/helpers-$(_TARGET_NAME).bc

_QEMU_TARGET := $(_TARGET_NAME)-softmmu

include $(qemu_build_dir)/$(_QEMU_TARGET)/Makefile

_INCLUDES := -I$(qemu_build_dir) -I$(qemu_build_dir)/$(_QEMU_TARGET) -I$(SRC_PATH)/target-$(TARGET_BASE_ARCH) $(QEMU_INCLUDES)
_CFLAGS   := $(QEMU_CFLAGS) -DNEED_CPU_H

#
# build library (QEMU bitcode + C file)
#

$(build_dir)/libqemutcg-$(_TARGET_NAME).bc: $(build_dir)/libqemutcg-$(_TARGET_NAME).1.bc
	$(llvm_build_dir)/bin/opt -o $@ -O3 $<

$(build_dir)/libqemutcg-$(_TARGET_NAME).1.bc: $(build_dir)/libqemutcg-$(_TARGET_NAME).0.bc
	$(build_dir)/llknife -o $@ -i $< --only-external-regex 'libqemutcg_.*'

$(build_dir)/libqemutcg-$(_TARGET_NAME).0.bc: $(build_dir)/qemu-$(_TARGET_NAME).bc $(build_dir)/qemutcg-$(_TARGET_NAME).bc
	@echo BCLINK $(notdir $@ $^)
	@$(llvm_build_dir)/bin/llvm-link -o $@ $^

$(build_dir)/qemutcg-$(_TARGET_NAME).bc: $(build_dir)/qemutcg.c
	@echo BC $(notdir $@ $^)
	$(CC) -o $@ -c -emit-llvm -Wall -O3 $(_INCLUDES) $(_CFLAGS) $<

#
# helper bitcode
#

$(build_dir)/helpers-$(_TARGET_NAME).bc: $(build_dir)/helpers-$(_TARGET_NAME).1.bc
	$(llvm_build_dir)/bin/opt -o $@ -O3 $<

$(build_dir)/helpers-$(_TARGET_NAME).1.bc: $(build_dir)/helpers-$(_TARGET_NAME).0.bc
	$(build_dir)/llknife -o $@ -i $< --change-fn-def-to-decl-regex '\(helper_.*mmu\)\|\(raise_interrupt.*\)\|\(raise_exception.*\)'

$(build_dir)/helpers-$(_TARGET_NAME).0.bc: $(build_dir)/qemu-$(_TARGET_NAME).5.bc
	$(build_dir)/llknife -o $@ -i $< --only-external-regex 'helper_.*'

#
# QEMU bitcode for library
#

$(build_dir)/qemu-$(_TARGET_NAME).bc: $(build_dir)/qemu-$(_TARGET_NAME).5.bc
	$(build_dir)/llknife -o $@ -i $< --change-fn-def-to-decl-regex 'helper_.*'

#
# process bitcode
#

$(build_dir)/qemu-$(_TARGET_NAME).5.bc: $(build_dir)/qemu-$(_TARGET_NAME).4.bc
	$(llvm_build_dir)/bin/opt -o $@ -O3 $<

$(build_dir)/qemu-$(_TARGET_NAME).4.bc: $(build_dir)/qemu-$(_TARGET_NAME).3.bc
	$(build_dir)/llknife -o $@ -i $< --set-global-constant-regex 'qemu_loglevel.*'

$(build_dir)/qemu-$(_TARGET_NAME).3.bc: $(build_dir)/qemu-$(_TARGET_NAME).2.bc
	$(build_dir)/llknife -o $@ -i $< --remove-noinline-attr-regex '.*qemu_loglevel.*'

$(build_dir)/qemu-$(_TARGET_NAME).2.bc: $(build_dir)/qemu-$(_TARGET_NAME).1.bc
	$(build_dir)/llknife -o $@ -i $< --delete-global-ctors

$(build_dir)/qemu-$(_TARGET_NAME).1.bc: $(build_dir)/qemu-$(_TARGET_NAME).0.bc
	$(build_dir)/llknife -o $@ -i $< --change-fn-def-to-decl-regex '\(cpu_ld.*\)\|\(x86_st.*_phys\)\|\(x86_ld.*_phys\)\|\(address_space_.*\)\|\(helper_set_dr\)\|\(helper_iret.*\)\|\(helper_lcall_.*\)\|\(helper_vm.*\)\|\(helper_ljmp_protected\)'

$(build_dir)/qemu-$(_TARGET_NAME).0.bc:
	@echo BCLINK $@ $(sort $(notdir $@ $(patsubst %,$(qemu_build_dir)/$(_QEMU_TARGET)/%,$(all-obj-y)) $(build_dir)/qemustub.weak.bc $(build_dir)/qemuutil.weak.bc))
	@$(llvm_build_dir)/bin/llvm-link -o $@ $(sort $(patsubst %,$(qemu_build_dir)/$(_QEMU_TARGET)/%,$(all-obj-y))) $(build_dir)/qemustub.weak.bc $(build_dir)/qemuutil.weak.bc
