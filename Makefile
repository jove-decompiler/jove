# this just obtains the directory this Makefile resides in
JOVE_ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

include gmsl

include $(JOVE_ROOT_DIR)/version.mk
include $(JOVE_ROOT_DIR)/targets.mk

define include_target_helpers_template
include $(JOVE_ROOT_DIR)/lib/arch/$(1)/helpers.mk
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call include_target_helpers_template,$(t))))

LLVM_BIN_DIR := $(JOVE_ROOT_DIR)/llvm-project/build/bin

LLVM_DIS := $(LLVM_BIN_DIR)/llvm-dis
LLVM_CC  := $(LLVM_BIN_DIR)/clang
LLVM_LLD := $(LLVM_BIN_DIR)/ld.lld
LLVM_LLC := $(LLVM_BIN_DIR)/llc
LLVM_CXX := $(LLVM_BIN_DIR)/clang++
LLVM_OPT := $(LLVM_BIN_DIR)/opt
LLVM_LLD_LINK := $(LLVM_BIN_DIR)/lld-link

jove_tool = $(LLVM_BIN_DIR)/jove-$(1)

JOVE_GITVER := $(shell git log -n1 --format="%h")

BINDIR := bin

$(foreach t,$(ALL_TARGETS),$(shell mkdir -p $(BINDIR)/$(t)/helpers))

mipsel_ARCH_CFLAGS   := -D TARGET_MIPS32
mips_ARCH_CFLAGS     := -D TARGET_MIPS32
mips64el_ARCH_CFLAGS := -D TARGET_MIPS64

runtime_cflags = -std=gnu99 \
                 --target=$($(1)_TRIPLE) \
                 -I include \
                 -I lib \
                 -I lib/arch/$(1) \
                 -I boost/libs/preprocessor/include/ \
                 -D TARGET_$(call uc,$(1)) \
                 -D TARGET_ARCH_NAME=\"$(1)\" \
                 $($(1)_ARCH_CFLAGS) \
                 -D _GNU_SOURCE \
                 -D _LARGEFILE64_SOURCE \
                 -Weverything \
                 -Werror-implicit-function-declaration \
                 -Werror=return-type \
                 -Wno-declaration-after-statement \
                 -Wno-unsafe-buffer-usage \
                 -Wno-reserved-macro-identifier \
                 -Wno-used-but-marked-unused \
                 -Wno-reserved-identifier \
                 -Wno-visibility \
                 -Wno-unused-function \
                 -Wno-unused-macros \
                 -Wno-language-extension-token \
                 -Wno-missing-prototypes \
                 -Wno-missing-variable-declarations \
                 -Wno-gnu-zero-variadic-macro-arguments \
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

STARTER_LDFLAGS := -fuse-ld=lld \
                   -nostdlib \
                   -Wl,-e,_start \
                   -static

runtime_so_ldflags = -nostdlib \
                     -soname=libjove_rt.so \
                     -init _jove_rt_init \
                     --push-state \
                     --as-needed $(JOVE_ROOT_DIR)/prebuilts/obj/libclang_rt.builtins-$(1).a \
                     --pop-state \
                     --exclude-libs ALL \
                     -shared

runtime_dll_ldflags = /dll \
                      /machine:$($(1)_COFF_MACHINE) \
                      /nodefaultlib \
                      /debug:dwarf \
                      /WX:no \
                      /largeaddressaware \
                      /opt:noref \
                      /opt:noicf \
                      /auto-import:no \
                      /runtime-pseudo-reloc:no

# disable built-in rules
.SUFFIXES:

.PHONY: all
all: helpers \
     runtime \
     qemu-starters \
     dump-vdsos

.PHONY: helpers
helpers: $(foreach t,$(ALL_TARGETS),helpers-$(t))

.PHONY: runtime
runtime: $(foreach t,$(ALL_TARGETS),runtime-$(t))

.PHONY: qemu-starters
qemu-starters: $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/qemu-starter)

.PHONY: dump-vdsos
dump-vdsos: $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/dump-vdso)

runtime_dlls = $(BINDIR)/$(1)/libjove_rt.st.dll
#               $(BINDIR)/$(1)/libjove_rt.mt.dll

_DLLS_x86_64 := $(call runtime_dlls,x86_64)
#_DLLS_i386   := $(call runtime_dlls,i386)

_DLL_i386_LIBGCC := /usr/lib/gcc/i686-w64-mingw32/12-win32/libgcc.a
_DLL_x86_64_LIBGCC := /usr/lib/gcc/x86_64-w64-mingw32/12-win32/libgcc.a

_DLL_x86_64_LINUX_CALL_CONV := X86_64_SysV
_DLL_i386_LINUX_CALL_CONV := C

define target_code_template
.PHONY: helpers-$(1)
helpers-$(1): $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).ll) \
              $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).bc)

.PHONY: runtime-$(1)
runtime-$(1): $(BINDIR)/$(1)/libjove_rt.st.so \
              $(BINDIR)/$(1)/libjove_rt.mt.so \
              $(BINDIR)/$(1)/jove.elf.st.bc \
              $(BINDIR)/$(1)/jove.elf.mt.bc \
              $(BINDIR)/$(1)/jove.elf.st.ll \
              $(BINDIR)/$(1)/jove.elf.mt.ll \
              $(BINDIR)/$(1)/jove.coff.st.bc \
              $(BINDIR)/$(1)/jove.coff.mt.bc \
              $(BINDIR)/$(1)/jove.coff.st.ll \
              $(BINDIR)/$(1)/jove.coff.mt.ll \
              $(_DLLS_$(1))

$(BINDIR)/$(1)/qemu-starter: lib/arch/$(1)/qemu-starter.c
	clang-16 -o $$@ $(call runtime_cflags,$(1)) $(STARTER_LDFLAGS) $$<
	llvm-strip-16 $$@

$(BINDIR)/$(1)/dump-vdso: lib/arch/$(1)/dump-vdso.c
	clang-16 -o $$@ $(call runtime_cflags,$(1)) $(STARTER_LDFLAGS) $$<
	llvm-strip-16 $$@

$(BINDIR)/$(1)/qemu-starter.inc: $(BINDIR)/$(1)/qemu-starter
	xxd -i < $$< > $$@

$(BINDIR)/$(1)/dump-vdso.inc: $(BINDIR)/$(1)/dump-vdso
	xxd -i < $$< > $$@

#
# starter bitcode
#
$(BINDIR)/$(1)/jove.elf.st.bc: lib/arch/$(1)/jove.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -MMD $$<

$(BINDIR)/$(1)/jove.elf.mt.bc: lib/arch/$(1)/jove.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -D JOVE_MT -MMD $$<

$(BINDIR)/$(1)/jove.coff.st.bc: lib/arch/$(1)/jove.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -D JOVE_COFF -MMD $$<

$(BINDIR)/$(1)/jove.coff.mt.bc: lib/arch/$(1)/jove.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -D JOVE_COFF -D JOVE_MT -MMD $$<

$(BINDIR)/$(1)/jove.%.ll: $(BINDIR)/$(1)/jove.%.bc
	$(LLVM_OPT) -o $$@ -S --strip-debug $$<

#
# runtime bitcode
#
$(BINDIR)/$(1)/libjove_rt.elf.st.bc: lib/arch/$(1)/rt.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -MMD $$<

$(BINDIR)/$(1)/libjove_rt.elf.mt.bc: lib/arch/$(1)/rt.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -D JOVE_MT -MMD $$<

$(BINDIR)/$(1)/libjove_rt.coff.st.bc: lib/arch/$(1)/rt.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -D JOVE_COFF -MMD $$<

$(BINDIR)/$(1)/libjove_rt.coff.mt.bc: lib/arch/$(1)/rt.c
	$(LLVM_CC) -o $$@ -c -emit-llvm $(call runtime_cflags,$(1)) -D JOVE_COFF -D JOVE_MT -MMD $$<

#
# runtime shared libraries
#
$(BINDIR)/$(1)/libjove_rt.%.so.o: $(BINDIR)/$(1)/libjove_rt.elf.%.bc
	$(LLVM_LLC) -o $$@ --filetype=obj --relocation-model=pic $$<

$(BINDIR)/$(1)/libjove_rt.%.so: $(BINDIR)/$(1)/libjove_rt.%.so.o
	$(LLVM_LLD) -o $$@ -m $($(1)_LD_EMU) $(call runtime_so_ldflags,$(1)) $$<

#
# runtime DLLs
#
$(BINDIR)/$(1)/libjove_rt.%.dll.o: $(BINDIR)/$(1)/libjove_rt.coff.%.bc \
                                   $(BINDIR)/$(1)/jove_rt_dll.callconv.syms \
                                   $(BINDIR)/$(1)/jove_rt_dll.dllexport.syms
	$(call jove_tool,$(1)) llknife -v -o $$<.2.tmp -i $$< --calling-convention=$(_DLL_$(1)_LINUX_CALL_CONV) $(BINDIR)/$(1)/jove_rt_dll.callconv.syms
	$(call jove_tool,$(1)) llknife -v -o $$<.3.tmp -i $$<.2.tmp --dllexport $(BINDIR)/$(1)/jove_rt_dll.dllexport.syms
	$(LLVM_DIS) -o $$<.dll.ll $$<.3.tmp
	$(LLVM_LLC) -o $$@ --filetype=obj --relocation-model=pic --mtriple=$($(1)_COFF_TRIPLE) $$<.3.tmp

$(BINDIR)/$(1)/libjove_rt.%.dll: $(BINDIR)/$(1)/libjove_rt.%.dll.o \
                                 $(BINDIR)/$(1)/libjove_rt.%.def
	$(LLVM_LLD_LINK) /out:$$@ /def:$$(patsubst %.dll,%.def,$$@) /verbose $(call runtime_dll_ldflags,$(1)) $$< $(_DLL_$(1)_LIBGCC)

.PHONY: gen-tcgconstants-$(1)
gen-tcgconstants-$(1): $(BINDIR)/$(1)/gen-tcgconstants
	$(BINDIR)/$(1)/gen-tcgconstants > include/jove/tcgconstants-$(1).h
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_code_template,$(t))))

-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.elf.st.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.elf.mt.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.coff.st.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/libjove_rt.coff.mt.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.elf.st.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.elf.mt.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.coff.st.d)
-include $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/jove.coff.mt.d)
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

CARBON_EXTRACT := /usr/local/bin/carbon-extract

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
	rm -f $(BINDIR)/$(1)/jove.*.ll        \
	      $(BINDIR)/$(1)/jove.*.bc        \
	      $(BINDIR)/$(1)/jove.*.d         \
	      $(BINDIR)/$(1)/libjove_rt.*.tmp \
	      $(BINDIR)/$(1)/libjove_rt.*.d   \
	      $(BINDIR)/$(1)/libjove_rt.*.o   \
	      $(BINDIR)/$(1)/libjove_rt.*.ll  \
	      $(BINDIR)/$(1)/libjove_rt.*.bc  \
	      $(BINDIR)/$(1)/libjove_rt.*.so  \
	      $(BINDIR)/$(1)/libjove_rt.*.dll \
	      $(BINDIR)/$(1)/libjove_rt.*.lib

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
