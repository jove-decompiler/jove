# this just obtains the directory this Makefile resides in
JOVE_ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

include gmsl

include $(JOVE_ROOT_DIR)/version.mk
include $(JOVE_ROOT_DIR)/config.mk

define include_target_helpers_template
include $(JOVE_ROOT_DIR)/lib/arch/$(1)/helpers.mk
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call include_target_helpers_template,$(t))))

LLVM_BIN_DIR := $(JOVE_ROOT_DIR)/llvm-project/build/bin

LLVM_DIS := $(LLVM_BIN_DIR)/llvm-dis
LLVM_CC  := $(LLVM_BIN_DIR)/clang
LLVM_CXX := $(LLVM_BIN_DIR)/clang++
LLVM_OPT := $(LLVM_BIN_DIR)/opt

JOVE_GITVER := $(shell git log -n1 --format="%h")

BINDIR := bin

$(foreach t,$(ALL_TARGETS),$(shell mkdir -p $(BINDIR)/$(t)/helpers))

mipsel_ARCH_CFLAGS   := -D TARGET_MIPS32
mips_ARCH_CFLAGS     := -D TARGET_MIPS32
mips64el_ARCH_CFLAGS := -D TARGET_MIPS64

# disable built-in rules
.SUFFIXES:

.PHONY: all
all: helpers \
     runtime \
     $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/qemu-starter)

.PHONY: helpers
helpers: $(foreach t,$(ALL_TARGETS),$(foreach h,$($(t)_HELPERS),$(BINDIR)/$(t)/helpers/$(h).bc)) \
         $(foreach t,$(ALL_TARGETS),$(foreach h,$($(t)_HELPERS),$(BINDIR)/$(t)/helpers/$(h).ll))

.PHONY: runtime
runtime: $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.so) \
         $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.bc)

define target_code_template
$(BINDIR)/$(1)/qemu-starter: lib/arch/$(1)/qemu-starter.c
	@echo CC $$<
	@clang-16 -o $$@ -Wall \
	                 -I lib -I lib/arch/$(1) \
	                 -nostdlib \
	                 --sysroot $($(1)_SYSROOT) \
	                 --target=$($(1)_TRIPLE) \
	                 -Ofast -g0 \
	                 -std=gnu99 \
	                 -ffreestanding \
	                 -fno-stack-protector \
	                 -fwrapv \
	                 -fuse-ld=lld \
	                 -Wl,-e,_start \
	                 -static $$<
	@llvm-strip-16 $$@

$(BINDIR)/$(1)/qemu-starter.inc: $(BINDIR)/$(1)/qemu-starter
	@xxd -i < $$< > $$@

$(BINDIR)/$(1)/libjove_rt.so: lib/arch/$(1)/rt.c
	@echo CC $$<
	@$(LLVM_CC) -o $$@ -Wall \
	                   -Werror-implicit-function-declaration \
	                   -I lib -I lib/arch/$(1) -I $($(1)_SYSROOT)/include \
	                   -nostdlib \
	                   --sysroot $($(1)_SYSROOT) \
	                   --target=$($(1)_TRIPLE) \
	                   -Ofast -g \
	                   -std=gnu99 \
	                   -D TARGET_$(call uc,$(1)) \
	                   -D TARGET_ARCH_NAME=\"$(1)\" \
	                   $($(1)_ARCH_CFLAGS) \
	                   -ffreestanding \
	                   -fno-stack-protector \
	                   -fno-delete-null-pointer-checks \
	                   -fwrapv \
	                   -Bsymbolic \
	                   -MMD \
	                   -fPIC \
	                   -fuse-ld=lld \
	                   -shared $$< \
	                   -Wl,-soname=libjove_rt.so \
	                   -Wl,-init,_jove_rt_init \
	                   -Wl,--push-state \
	                   -Wl,--as-needed $(JOVE_ROOT_DIR)/prebuilts/obj/libclang_rt.builtins-$(1).a \
	                   -Wl,--pop-state \
	                   -Wl,--exclude-libs,ALL

$(BINDIR)/$(1)/jove.bc: lib/arch/$(1)/jove.c
	@echo CC $$<
	@$(LLVM_CC) -o $$@ -Wall \
	                   -Werror-implicit-function-declaration \
	                   -I lib -I include -I boost-preprocessor/include \
	                   --sysroot $($(1)_SYSROOT) \
	                   --target=$($(1)_TRIPLE) \
	                   -Ofast -g \
	                   -std=gnu99 \
	                   -D TARGET_$(call uc,$(1)) \
	                   -D TARGET_ARCH_NAME=\"$(1)\" \
	                   $($(1)_ARCH_CFLAGS) \
	                   -ffreestanding \
	                   -fno-stack-protector \
	                   -fno-delete-null-pointer-checks \
	                   -fwrapv \
	                   -fno-plt \
	                   -MMD \
	                   -c -emit-llvm $$<

.PHONY: gen-tcgconstants-$(1)
gen-tcgconstants-$(1): $(BINDIR)/$(1)/gen-tcgconstants
	@echo GEN $@
	@$(BINDIR)/$(1)/gen-tcgconstants > include/jove/tcgconstants-$(1).h
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_code_template,$(t))))

-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.d)
-include $(foreach t,$(ALL_TARGETS),$(foreach h,$($(t)_HELPERS),$(BINDIR)/$(t)/helpers/$(h).d))

.PHONY: clean
clean: clean-helpers
	rm -f $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.so) \
	      $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/qemu-starter) \
	      $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/*.bc) \
	      $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/*.d)

.PHONY: clean-helpers
clean-helpers:
	rm -f $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/helpers/*.c) \
	      $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/helpers/*.bc) \
	      $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/helpers/*.d) \
	      $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/helpers/*.ll)

.PHONY: distclean
distclean: clean
	rm -f jove-v*.tar \
	      jove-v*.tar.xz

.PHONY: check
check:
	$(MAKE) -C $(JOVE_ROOT_DIR)/tests check

#
# TCG
#

CARBON_EXTRACT := $(JOVE_ROOT_DIR)/carbon-copy/build/extract/carbon-extract

QEMU_DIR := $(JOVE_ROOT_DIR)/qemu
qemu_carbon_build_dir = $(QEMU_DIR)/$(1)_carbon_build

define target_template
$(BINDIR)/$(1)/helpers/%.ll: $(BINDIR)/$(1)/helpers/%.bc
	@echo DIS $$<
	@$(LLVM_OPT) -o $$@ -S --strip-debug $$<

$(BINDIR)/$(1)/helpers/%.bc: $(BINDIR)/$(1)/helpers/%.c
	@echo BC $$<
	@$(LLVM_CC) -o $$@ -Wall \
	                   -Werror-implicit-function-declaration \
	                   -Wno-initializer-overrides \
	                   -Wno-macro-redefined \
	                   -Wno-typedef-redefinition \
	                   -Wno-unused-function \
	                   -Wno-unknown-attributes \
	                   -Wno-atomic-alignment \
	                   -I lib -I lib/arch/$(1) \
	                   --sysroot $($(1)_SYSROOT) \
	                   --target=$($(1)_TRIPLE) \
	                   -O3 -g \
	                   -std=gnu99 \
	                   -DNEED_CPU_H \
	                   -DNDEBUG \
	                   -ffreestanding \
	                   -fno-stack-protector \
	                   -fno-strict-aliasing \
	                   -fno-common \
	                   -fwrapv \
	                   -MMD \
	                   -c -emit-llvm $$<
	@$(LLVM_OPT) -o $$@.tmp $$@ -internalize -internalize-public-api-list=helper_$$*
	@$(LLVM_OPT) -o $$@ -O3 $$@.tmp
	@rm $$@.tmp

$(BINDIR)/$(1)/helpers/%.c:
	$(CARBON_EXTRACT) --src $(QEMU_DIR) --bin $(call qemu_carbon_build_dir,$(1)) helper_$$* $$($(1)-$$*_EXTRICATE_ARGS) > $$@

.PHONY: check-helper-$(1)-%
check-helper-$(1)-%: $(BINDIR)/$(1)/helpers/%.bc
	$(LLVM_BIN_DIR)/jove-$(1) check-helper --vars $$*

.PHONY: extract-helpers-$(1)
extract-helpers-$(1): $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).c)

.PHONY: check-helpers-$(1)
check-helpers-$(1): $(foreach h,$($(1)_HELPERS),check-helper-$(1)-$(h))

.PHONY: clean-helpers-$(1)
clean-helpers-$(1):
	rm -f $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).c)
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_template,$(t))))

.PHONY: check-helpers
check-helpers: $(foreach t,$(ALL_TARGETS),check-$(t))

.PHONY: gen-tcgconstants
gen-tcgconstants: $(foreach t,$(ALL_TARGETS),gen-tcgconstants-$(t))
