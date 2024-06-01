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

runtime_cflags = -std=gnu99 \
                 --sysroot $($(1)_SYSROOT) \
                 --target=$($(1)_TRIPLE) \
                 -I include \
                 -I lib \
                 -I lib/arch/$(1) \
                 -I $($(1)_SYSROOT)/include \
                 -I boost/libs/preprocessor/include/ \
                 -D TARGET_$(call uc,$(1)) \
                 -D TARGET_ARCH_NAME=\"$(1)\" \
                 $($(1)_ARCH_CFLAGS) \
                 -Wall \
                 -Werror-implicit-function-declaration \
                 -Wno-visibility \
                 -Ofast \
                 -gline-tables-only \
                 -gdwarf-4 \
                 -ffreestanding \
                 -fno-strict-aliasing \
                 -fno-stack-protector \
                 -fno-delete-null-pointer-checks \
                 -fwrapv \
                 -fno-plt \
                 -fPIC

COMMON_LDFLAGS := -fuse-ld=lld \
                  -nostdlib \
                  -Bsymbolic

STARTER_LDFLAGS := $(COMMON_LDFLAGS) \
                   -Wl,-e,_start \
                   -static

runtime_ldflags = $(COMMON_LDFLAGS) \
                  -Wl,-soname=libjove_rt.so \
                  -Wl,-init,_jove_rt_init \
                  -Wl,--push-state \
                  -Wl,--as-needed $(JOVE_ROOT_DIR)/prebuilts/obj/libclang_rt.builtins-$(1).a \
                  -Wl,--pop-state \
                  -Wl,--exclude-libs,ALL \
                  -shared

# disable built-in rules
.SUFFIXES:

.PHONY: all
all: helpers \
     runtime \
     qemu-starters

.PHONY: helpers
helpers: $(foreach t,$(ALL_TARGETS),helpers-$(t))

.PHONY: runtime
runtime: $(foreach t,$(ALL_TARGETS),runtime-$(t))

.PHONY: qemu-starters
qemu-starters: $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/qemu-starter)

define target_code_template
.PHONY: helpers-$(1)
helpers-$(1): $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).ll) \
              $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).bc)

.PHONY: runtime-$(1)
runtime-$(1): $(BINDIR)/$(1)/libjove_rt.st.so \
              $(BINDIR)/$(1)/libjove_rt.mt.so \
              $(BINDIR)/$(1)/jove.st.bc \
              $(BINDIR)/$(1)/jove.mt.bc \
              $(BINDIR)/$(1)/jove.st.ll \
              $(BINDIR)/$(1)/jove.mt.ll

$(BINDIR)/$(1)/qemu-starter: lib/arch/$(1)/qemu-starter.c
	clang-16 -o $$@ $(call runtime_cflags,$(1)) $(STARTER_LDFLAGS) $$<
	llvm-strip-16 $$@

$(BINDIR)/$(1)/qemu-starter.inc: $(BINDIR)/$(1)/qemu-starter
	xxd -i < $$< > $$@

$(BINDIR)/$(1)/libjove_rt.st.so: lib/arch/$(1)/rt.c
	$(LLVM_CC) -o $$@ $(call runtime_cflags,$(1)) $(call runtime_ldflags,$(1)) -MMD $$<

$(BINDIR)/$(1)/libjove_rt.mt.so: lib/arch/$(1)/rt.c
	$(LLVM_CC) -o $$@ $(call runtime_cflags,$(1)) $(call runtime_ldflags,$(1)) -D JOVE_MT -MMD $$<

$(BINDIR)/$(1)/jove.st.bc: lib/arch/$(1)/jove.c
	$(LLVM_CC) -o $$@ $(call runtime_cflags,$(1)) -MMD -c -emit-llvm $$<

$(BINDIR)/$(1)/jove.mt.bc: lib/arch/$(1)/jove.c
	$(LLVM_CC) -o $$@ $(call runtime_cflags,$(1)) -D JOVE_MT -MMD -c -emit-llvm $$<

$(BINDIR)/$(1)/jove.%.ll: $(BINDIR)/$(1)/jove.%.bc
	$(LLVM_OPT) -o $$@ -S --strip-debug $$<

.PHONY: gen-tcgconstants-$(1)
gen-tcgconstants-$(1): $(BINDIR)/$(1)/gen-tcgconstants
	$(BINDIR)/$(1)/gen-tcgconstants > include/jove/tcgconstants-$(1).h
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_code_template,$(t))))

-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.st.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.mt.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.st.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.mt.d)
-include $(foreach t,$(ALL_TARGETS),$(foreach h,$($(t)_HELPERS),$(BINDIR)/$(t)/helpers/$(h).d))

.PHONY: clean-helpers
clean-helpers: $(foreach t,$(ALL_TARGETS),clean-helpers-$(t))

.PHONY: clean-runtime
clean-runtime: $(foreach t,$(ALL_TARGETS),clean-runtime-$(t))

.PHONY: clean-bitcode
clean-bitcode: $(foreach t,$(ALL_TARGETS),clean-bitcode-$(t))

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
helper_cflags = $(call runtime_cflags,$(1)) \
                -Wno-initializer-overrides \
                -Wno-macro-redefined \
                -Wno-typedef-redefinition \
                -Wno-unused-function \
                -Wno-unknown-attributes \
                -Wno-atomic-alignment \
                -DNEED_CPU_H \
                -DNDEBUG

CARBON_EXTRACT := $(JOVE_ROOT_DIR)/carbon-copy/build/extract/carbon-extract

QEMU_DIR := $(JOVE_ROOT_DIR)/qemu
qemu_carbon_build_dir = $(QEMU_DIR)/$(1)_carbon_build

define target_template
$(BINDIR)/$(1)/helpers/%.ll: $(BINDIR)/$(1)/helpers/%.bc
	$(LLVM_OPT) -o $$@ -S --strip-debug $$<

$(BINDIR)/$(1)/helpers/%.bc: $(BINDIR)/$(1)/helpers/%.c
	@echo BC $$<
	@$(LLVM_CC) -o $$@ $(call helper_cflags,$(1)) -MMD -c -emit-llvm $$<
	@$(LLVM_OPT) -o $$@.tmp $$@ -passes=internalize --internalize-public-api-list=helper_$$*
	@$(LLVM_OPT) -o $$@ -O3 $$@.tmp
	@rm $$@.tmp

$(BINDIR)/$(1)/helpers/%.c:
	@mkdir -p $(BINDIR)/$(1)/helpers
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

.PHONY: clean-runtime-$(1)
clean-runtime-$(1):
	rm -f $(BINDIR)/$(1)/jove.st.ll \
	      $(BINDIR)/$(1)/jove.mt.ll \
	      $(BINDIR)/$(1)/jove.st.bc \
	      $(BINDIR)/$(1)/jove.mt.bc \
	      $(BINDIR)/$(1)/libjove_rt.st.so \
	      $(BINDIR)/$(1)/libjove_rt.mt.so

.PHONY: clean-bitcode-$(1)
clean-bitcode-$(1):
	rm -f $(BINDIR)/$(1)/*.bc \
	      $(BINDIR)/$(1)/*.ll \
	      $(BINDIR)/$(1)/helpers/*.bc \
	      $(BINDIR)/$(1)/helpers/*.ll
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_template,$(t))))

.PHONY: check-helpers
check-helpers: $(foreach t,$(ALL_TARGETS),check-$(t))

.PHONY: gen-tcgconstants
gen-tcgconstants: $(foreach t,$(ALL_TARGETS),gen-tcgconstants-$(t))
