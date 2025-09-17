# this just obtains the directory this Makefile resides in
JOVE_ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

include gmsl

include $(JOVE_ROOT_DIR)/version.mk
include $(JOVE_ROOT_DIR)/targets.mk

get_targets_for_platform = $(ALL_$(call uc,$1)_TARGETS)

define include_target_helpers_template
include $(JOVE_ROOT_DIR)/lib/arch/$(1)/helpers.mk
-include $(JOVE_ROOT_DIR)/bin/$(1)/all_helpers.mk
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call include_target_helpers_template,$(t))))

OUR_LLVM_BIN_DIR := $(JOVE_ROOT_DIR)/llvm-project/build/llvm/bin

OUR_LLVM_DIS := $(OUR_LLVM_BIN_DIR)/llvm-dis
OUR_LLVM_CC  := $(OUR_LLVM_BIN_DIR)/clang
OUR_LLVM_LLD := $(OUR_LLVM_BIN_DIR)/ld.lld
OUR_LLVM_LLC := $(OUR_LLVM_BIN_DIR)/llc
OUR_LLVM_CXX := $(OUR_LLVM_BIN_DIR)/clang++
OUR_LLVM_OPT := $(OUR_LLVM_BIN_DIR)/opt
OUR_LLVM_LLD_LINK := $(OUR_LLVM_BIN_DIR)/lld-link

jove_tool = $(OUR_LLVM_BIN_DIR)/jove-$(1)

JOVE_GITVER := $(shell git log -n1 --format="%h")

BINDIR := bin

mipsel_RUNTIME_CFLAGS   := -D TARGET_MIPS32
mips_RUNTIME_CFLAGS     := -D TARGET_MIPS32
mips64el_RUNTIME_CFLAGS := -D TARGET_MIPS64

mips_RUNTIME_CFLAGS   += -mno-check-zero-division
mipsel_RUNTIME_CFLAGS += -mno-check-zero-division

runtime_cflags = -std=gnu11 \
                 -I include \
                 -I lib \
                 -I lib/arch/$(1) \
                 -I $(BINDIR)/$(1) \
                 -I boost/libs/preprocessor/include/ \
                 -D TARGET_$(call uc,$(1)) \
                 -D TARGET_ARCH_NAME=\"$(1)\" \
                 $($(1)_RUNTIME_CFLAGS) \
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
                 -O3 \
                 -g \
                 -ggdb \
                 -gdwarf-4 \
                 -ffreestanding \
                 -fno-strict-aliasing \
                 -fno-stack-protector \
                 -fno-stack-check \
                 -fno-delete-null-pointer-checks \
                 -fno-strict-overflow \
                 -fno-plt

UTILS_LDFLAGS := -fuse-ld=lld \
                 -nostdlib \
                 -Wl,-e,_jove_start \
                 -static

runtime_so_ldflags = -nostdlib \
                     -soname=libjove_rt.so \
                     -init _jove_rt_init \
                     $($(1)_RUNTIME_SO_LDFLAGS) \
                     --push-state \
                     --as-needed $($(1)_LIBGCC) \
                     --pop-state \
                     --exclude-libs ALL \
                     -shared

runtime_dll_ldflags = /dll \
                      /machine:$($(1)_COFF_MACHINE) \
                      /nodefaultlib \
                      /debug:dwarf \
                      /WX:no \
                      /safeseh:no \
                      /largeaddressaware \
                      /opt:noref \
                      /opt:noicf \
                      /auto-import:no \
                      /runtime-pseudo-reloc:no

#
# find utilities
#
UTILSRCDIR := utilities
UTILSRCS   := $(wildcard $(UTILSRCDIR)/*.c)
UTILS      := $(patsubst $(UTILSRCDIR)/%.c,%,$(UTILSRCS))
UTILBINS   := $(foreach t,$(ALL_TARGETS),$(foreach util,$(UTILS),$(BINDIR)/$(t)/$(util)))
UTILINCS   := $(foreach t,$(ALL_TARGETS),$(foreach util,$(UTILS),$(BINDIR)/$(t)/$(util).inc))
UTILDEPS   := $(foreach t,$(ALL_TARGETS),$(foreach util,$(UTILS),$(BINDIR)/$(t)/$(util).d))

# disable built-in rules
.SUFFIXES:

.PHONY: all
all: helpers \
     runtime \
     utilities

$(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),$(shell mkdir -p $(BINDIR)/$(t)/helpers/$(p))))

.PHONY: helpers
helpers: $(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),helpers-$(t)-$(p)))

.PHONY: runtime
runtime: $(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),runtime-$(t)-$(p)))

.PHONY: softfpu
softfpu: $(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),$(BINDIR)/$(t)/softfpu-$(p).o))

.PHONY: utilities
utilities: $(UTILBINS) $(UTILINCS)

.PHONY: asm-offsets
asm-offsets: $(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),$(BINDIR)/$(t)/asm-offsets-$(p).h))

.PHONY: tcg-constants
tcg-constants: $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/tcgconstants.h) \
               $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(HOST_TARGET)/tcgconstants.$(t).h)

.PHONY: all-helpers-mk
all-helpers-mk: $(foreach t,$(ALL_TARGETS),all-helpers-$(t)-mk)

.PHONY: env-inits
env-inits: $(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),$(BINDIR)/$(t)/env_init.$(p).inc))

.PHONY: version
version: $(BINDIR)/version.inc

$(BINDIR)/version.inc:
	@mkdir -p $(dir $@)
	@echo 'Generating $@...'
	@printf 'VERS("%s", "%s")\n' jove $(shell git rev-parse HEAD) > $@
	@git submodule status | awk '{printf "VERS(\"%s\", \"%s\")\n", $$2, $$1}' >> $@

_DLL_x86_64_LINUX_CALL_CONV := X86_64_SysV
_DLL_i386_LINUX_CALL_CONV := C

include lib/asm-offsets.mk

define target_code_template
.PHONY: helpers-$(1)-linux
helpers-$(1)-linux: $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/linux/$(h).ll) \
                    $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/linux/$(h).bc) \
                    $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).c)
.PHONY: helpers-$(1)-win
helpers-$(1)-win: $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/win/$(h).ll) \
                  $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/win/$(h).bc) \
                  $(foreach h,$($(t)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).c)

.PHONY: runtime-$(1)-win
runtime-$(1)-win: $(BINDIR)/$(1)/libjove_rt.st.dll \
                  $(BINDIR)/$(1)/libjove_rt.mt.dll \
                  $(BINDIR)/$(1)/jove.coff.st.bc \
                  $(BINDIR)/$(1)/jove.coff.st.ll \
                  $(BINDIR)/$(1)/jove.coff.mt.bc \
                  $(BINDIR)/$(1)/jove.coff.mt.ll

.PHONY: runtime-$(1)-linux
runtime-$(1)-linux: $(BINDIR)/$(1)/libjove_rt.st.so \
                    $(BINDIR)/$(1)/libjove_rt.mt.so \
                    $(BINDIR)/$(1)/jove.elf.st.bc \
                    $(BINDIR)/$(1)/jove.elf.mt.bc \
                    $(BINDIR)/$(1)/jove.elf.st.ll \
                    $(BINDIR)/$(1)/jove.elf.mt.ll

$(BINDIR)/$(1)/%: $(UTILSRCDIR)/%.c | ccopy
	clang-19 -o $$@ --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fpie $$< $(UTILS_LDFLAGS)

$(BINDIR)/$(1)/%.inc: $(BINDIR)/$(1)/%
	xxd -i < $$< > $$@

#
# we use clang-16 here to avoid a catch-22 during build. if our clang's version
# ever changes, we should change this, too.
#
$(BINDIR)/$(1)/asm-offsets-win.h: lib/arch/$(1)/asm-offsets.c | ccopy
	clang-16 -o $(BINDIR)/$(1)/asm-offsets-win.s --target=$($(1)_COFF_TRIPLE) $(call runtime_cflags,$(1)) -fverbose-asm -S lib/arch/$(1)/asm-offsets.c
	@echo "#pragma once" > $$@
	@sed -ne $(value sed-offsets) < $(BINDIR)/$(1)/asm-offsets-win.s >> $$@

$(BINDIR)/$(1)/asm-offsets-linux.h: lib/arch/$(1)/asm-offsets.c | ccopy
	clang-16 -o $(BINDIR)/$(1)/asm-offsets-linux.s --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fverbose-asm -S lib/arch/$(1)/asm-offsets.c
	@echo "#pragma once" > $$@
	@sed -ne $(value sed-offsets) < $(BINDIR)/$(1)/asm-offsets-linux.s >> $$@

#
# starter bitcode
#
$(BINDIR)/$(1)/jove.elf.st.bc: lib/arch/$(1)/jove.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -MMD $$<

$(BINDIR)/$(1)/jove.elf.mt.bc: lib/arch/$(1)/jove.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -D JOVE_MT -MMD $$<

$(BINDIR)/$(1)/jove.coff.st.bc: lib/arch/$(1)/jove.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -fdeclspec -D JOVE_COFF -MMD $$<
	$(call jove_tool,$(1)) llknife -v -o $$@ -i $$@ --calling-convention=$(_DLL_$(1)_LINUX_CALL_CONV) $(BINDIR)/$(1)/jove.coff.callconv.st.syms

$(BINDIR)/$(1)/jove.coff.mt.bc: lib/arch/$(1)/jove.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -fdeclspec -D JOVE_COFF -D JOVE_MT -MMD $$<
	$(call jove_tool,$(1)) llknife -v -o $$@ -i $$@ --calling-convention=$(_DLL_$(1)_LINUX_CALL_CONV) $(BINDIR)/$(1)/jove.coff.callconv.mt.syms

$(BINDIR)/$(1)/jove.%.ll: $(BINDIR)/$(1)/jove.%.bc
	$(OUR_LLVM_OPT) -o $$@ -S --strip-debug $$<

#
# runtime bitcode
#
$(BINDIR)/$(1)/libjove_rt.elf.st.bc: lib/arch/$(1)/rt.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -MMD $$<

$(BINDIR)/$(1)/libjove_rt.elf.mt.bc: lib/arch/$(1)/rt.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -D JOVE_MT -MMD $$<

$(BINDIR)/$(1)/libjove_rt.coff.st.bc: lib/arch/$(1)/rt.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -fdeclspec -D JOVE_COFF -MMD $$<

$(BINDIR)/$(1)/libjove_rt.coff.mt.bc: lib/arch/$(1)/rt.c | ccopy asm-offsets
	$(OUR_LLVM_CC) -o $$@ -c -emit-llvm --target=$($(1)_TRIPLE) $(call runtime_cflags,$(1)) -fPIC -fdeclspec -D JOVE_COFF -D JOVE_MT -MMD $$<

#
# runtime shared libraries
#
$(BINDIR)/$(1)/libjove_rt.%.so.o: $(BINDIR)/$(1)/libjove_rt.elf.%.bc
	$(OUR_LLVM_LLC) -o $$@ --dwarf-version=4 --filetype=obj --relocation-model=pic $$<

$(BINDIR)/$(1)/libjove_rt.%.so: $(BINDIR)/$(1)/libjove_rt.%.so.o
	$(OUR_LLVM_LLD) -o $$@ -m $($(1)_LD_EMU) $(call runtime_so_ldflags,$(1)) $$<

#
# runtime DLLs
#
$(BINDIR)/$(1)/libjove_rt.%.dll.o: $(BINDIR)/$(1)/libjove_rt.coff.%.bc \
                                   $(BINDIR)/$(1)/jove_rt_dll.callconv.%.syms \
                                   $(BINDIR)/$(1)/jove_rt_dll.dllexport.%.syms
	$(call jove_tool,$(1)) llknife -v -o $$<.2.tmp -i $$< --calling-convention=$(_DLL_$(1)_LINUX_CALL_CONV) $(BINDIR)/$(1)/jove_rt_dll.callconv.$$*.syms
	$(call jove_tool,$(1)) llknife -v -o $$<.3.tmp -i $$<.2.tmp --dllexport $(BINDIR)/$(1)/jove_rt_dll.dllexport.$$*.syms
	$(OUR_LLVM_DIS) -o $$<.dll.ll $$<.3.tmp
	$(OUR_LLVM_LLC) -o $$@ --dwarf-version=4 --filetype=obj --relocation-model=pic --mtriple=$($(1)_COFF_TRIPLE) $$<.3.tmp

$(BINDIR)/$(1)/libjove_rt.%.dll: $(BINDIR)/$(1)/libjove_rt.%.dll.o \
                                 $(BINDIR)/$(1)/libjove_rt.%.def
	$(OUR_LLVM_LLD_LINK) /out:$$@ /def:$$(patsubst %.dll,%.def,$$@) /verbose $(call runtime_dll_ldflags,$(1)) $$< $(_DLL_$(1)_LIBGCC)
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
-include $(foreach t,$(ALL_TARGETS),$(foreach h,$($(t)_HELPERS),$(BINDIR)/$(t)/helpers/linux/$(h).d))
-include $(foreach t,$(ALL_TARGETS),$(foreach h,$($(t)_HELPERS),$(BINDIR)/$(t)/helpers/win/$(h).d))

.PHONY: clean-helpers
clean-helpers: $(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),clean-helpers-$(t)-$(p)))

.PHONY: clean-runtime
clean-runtime: $(foreach t,$(ALL_TARGETS),clean-runtime-$(t))

.PHONY: clean-bitcode
clean-bitcode: $(foreach t,$(ALL_TARGETS),clean-bitcode-$(t))

.PHONY: clean-asm-offsets
clean-asm-offsets: $(foreach p,$(PLATFORMS),$(foreach t,$(call get_targets_for_platform,$(p)),clean-asm-offsets-$(t)-$(p)))

.PHONY: clean-utilities
clean-utilities:
	rm -f $(UTILINCS) $(UTILBINS)

.PHONY: distclean
distclean: clean
	rm -f jove-v*.tar \
	      jove-v*.tar.xz

#
# TCG
#
helper_cflags = $(call runtime_cflags,$(1)) \
                -fPIC \
                -Wno-initializer-overrides \
                -Wno-macro-redefined \
                -Wno-typedef-redefinition \
                -Wno-unused-function \
                -Wno-unknown-attributes \
                -Wno-atomic-alignment \
                -DG_DISABLE_ASSERT \
                -DNEED_CPU_H \
                -DCONFIG_USER_ONLY \
                -DNDEBUG

CARBON_EXTRACT := /usr/local/bin/carbon-extract

QEMU_DIR := $(JOVE_ROOT_DIR)/qemu
qemu_carbon_build_dir = $(QEMU_DIR)/$(1)_carbon_build
qemu_carbon_host_build_dir = $(QEMU_DIR)/$(HOST_TARGET)_carbon_build_$(1)
qemu_softfpu_build_dir = $(QEMU_DIR)/$(1)_softfpu_$(2)_build
qemu_softfpu_bitcode = $(call qemu_softfpu_build_dir,$(1),$(2))/qemu-$(1).bitcode
softfpu_bitcode = $(call qemu_softfpu_build_dir,$(1),$(2))/libfpu_soft-$(1)-$(2)-user.a.p/fpu_softfloat.c.o

LINUX_DIR := $(JOVE_ROOT_DIR)/linux
linux_carbon_build_dir = $(LINUX_DIR)/$(1)_carbon_build

define target_template

$(BINDIR)/$(1)/helpers/linux/%.ll: $(BINDIR)/$(1)/helpers/linux/%.bc
	$(OUR_LLVM_OPT) -o $$@ -S --strip-debug $$<

$(BINDIR)/$(1)/helpers/win/%.ll: $(BINDIR)/$(1)/helpers/win/%.bc
	$(OUR_LLVM_OPT) -o $$@ -S --strip-debug $$<

$(BINDIR)/$(1)/qemu-$(1).bitcode.cut: $(call qemu_softfpu_bitcode,$(1),linux) | $(call softfpu_bitcode,$(1),linux)
	$(call jove_tool,$(1)) llknife -v -o $(BINDIR)/$(1)/softfpu.externals.txt -i $(call softfpu_bitcode,$(1),linux) --print-external
	$(call jove_tool,$(1)) llknife -v -o $$@.tmp.1 -i $(call qemu_softfpu_bitcode,$(1),linux) --erase-external $(BINDIR)/$(1)/softfpu.externals.txt
	rm $(BINDIR)/$(1)/softfpu.externals.txt
	$(call jove_tool,$(1)) llknife -v -o $$@.tmp.2 -i $$@.tmp.1 --erase-ctors-and-dtors
	rm $$@.tmp.1
	$(call jove_tool,$(1)) llknife -v -o $$@.tmp.3 -i $$@.tmp.2 --only-external 'helper_.*'
	rm $$@.tmp.2
	$(OUR_LLVM_OPT) -o $$@ -O3 $$@.tmp.3
	rm $$@.tmp.3

$(BINDIR)/$(1)/helpers/linux/%.bc: $(BINDIR)/$(1)/qemu-$(1).bitcode.cut
	$(OUR_LLVM_OPT) -o $$@.tmp $$< -passes=internalize --internalize-public-api-list=helper_$$*
	$(OUR_LLVM_OPT) -o $$@.dbg -O3 $$@.tmp
	@rm $$@.tmp
	$(OUR_LLVM_OPT) -o $$@ --strip-debug $$@.dbg

$(BINDIR)/$(1)/helpers/win/%.bc: $(BINDIR)/$(1)/qemu-$(1).bitcode.cut
	$(OUR_LLVM_OPT) -o $$@.tmp $$< -passes=internalize --internalize-public-api-list=helper_$$*
	$(OUR_LLVM_OPT) -o $$@.dbg -O3 $$@.tmp
	@rm $$@.tmp
	$(OUR_LLVM_OPT) -o $$@ --strip-debug $$@.dbg

$(BINDIR)/$(1)/helpers/%.c:
	@mkdir -p $(BINDIR)/$(1)/helpers
	$(CARBON_EXTRACT) --src $(QEMU_DIR) --bin $(call qemu_carbon_build_dir,$(1)) --notfound-empty helper_$$* $$($(1)-$$*_EXTRICATE_ARGS) -o $$@

.PHONY: check-helper-$(1)-%
check-helper-$(1)-%: $(BINDIR)/$(1)/helpers/linux/%.bc
	$(OUR_LLVM_BIN_DIR)/jove-$(1) check-helper --vars $$*

.PHONY: extract-helpers-$(1)
extract-helpers-$(1): $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).c)

.PHONY: check-helpers-$(1)
check-helpers-$(1): $(foreach h,$($(1)_HELPERS),check-helper-$(1)-$(h))

.PHONY: clean-helpers-$(1)-linux
clean-helpers-$(1)-linux:
	rm -f $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).c) \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/linux/$(h).bc) \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/linux/$(h).bc.dbg) \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/linux/$(h).ll) \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/linux/$(h).d)

.PHONY: clean-helpers-$(1)-win
clean-helpers-$(1)-win:
	rm -f $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/$(h).c)   \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/win/$(h).bc)  \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/win/$(h).bc.dbg) \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/win/$(h).ll) \
	      $(foreach h,$($(1)_HELPERS),$(BINDIR)/$(1)/helpers/win/$(h).d)

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
	      $(BINDIR)/$(1)/helpers/linux/*.bc \
	      $(BINDIR)/$(1)/helpers/linux/*.ll \
	      $(BINDIR)/$(1)/helpers/win/*.bc \
	      $(BINDIR)/$(1)/helpers/win/*.ll

.PHONY: clean-asm-offsets-$(1)-linux
clean-asm-offsets-$(1)-linux:
	rm -f $(BINDIR)/$(1)/asm-offsets-linux.h

.PHONY: clean-asm-offsets-$(1)-win
clean-asm-offsets-$(1)-win:
	rm -f $(BINDIR)/$(1)/asm-offsets-win.h

$(BINDIR)/$(1)/softfpu-linux.o: $(call softfpu_bitcode,$(1),linux)
	$(OUR_LLVM_LLC) -o $$@ --dwarf-version=4 --filetype=obj --trap-unreachable --relocation-model=pic $$<

$(BINDIR)/$(1)/softfpu-win.o: $(call softfpu_bitcode,$(1),linux)
	$(OUR_LLVM_LLC) -o $$@ --dwarf-version=4 --filetype=obj --trap-unreachable --relocation-model=pic --mtriple=$($(1)_COFF_TRIPLE) $$<

$(BINDIR)/$(1)/linux.copy.h:
	$(CARBON_EXTRACT) --src $(LINUX_DIR) --bin $(call linux_carbon_build_dir,$(1)) -n jove > $$@

$(BINDIR)/$(1)/env.copy.h:
	$(CARBON_EXTRACT) --src $(QEMU_DIR) --bin $(call qemu_carbon_build_dir,$(1)) -n jove_env > $$@

$(BINDIR)/$(1)/qemu.tcg.copy.h:
	@printf '%s\n\n' '#define CONFIG_USER_ONLY' > $$@
	$(CARBON_EXTRACT) --src $(QEMU_DIR) --bin $(call qemu_carbon_build_dir,$(1)) -n --flatten jove_tcg >> $$@

$(BINDIR)/$(HOST_TARGET)/qemu.tcg.copy.$(1).h:
	@printf '%s\n\n' '#define CONFIG_USER_ONLY' > $$@
	$(CARBON_EXTRACT) --src $(QEMU_DIR) --bin $(call qemu_carbon_host_build_dir,$(1)) -n --flatten jove_tcg >> $$@

$(BINDIR)/$(1)/tcgconstants.h: | $(BINDIR)/$(1)/qemu-starter
	env JOVE_PRINT_CONSTANTS=1 $(call qemu_carbon_build_dir,$(1))/qemu-$(1) $(BINDIR)/$(1)/qemu-starter > $$@

$(BINDIR)/$(HOST_TARGET)/tcgconstants.$(1).h: | $(BINDIR)/$(1)/qemu-starter
	env JOVE_PRINT_CONSTANTS=1 $(call qemu_carbon_host_build_dir,$(1))/qemu-$(1) $(BINDIR)/$(1)/qemu-starter > $$@

.PHONY: all-helpers-$(1)-mk
all-helpers-$(1)-mk: | $(call qemu_softfpu_bitcode,$(1),linux)
	printf '%s_HELPERS := ' '$(1)' > $(BINDIR)/$(1)/all_helpers.mk
	$(call jove_tool,$(1)) llknife -v -o $(BINDIR)/$(1)/all_helpers.txt -i $(call qemu_softfpu_bitcode,$(1),linux) --print-only 'helper_.*'
	sed 's/^helper_//' < $(BINDIR)/$(1)/all_helpers.txt | tr '\n' ' ' >> $(BINDIR)/$(1)/all_helpers.mk
	rm $(BINDIR)/$(1)/all_helpers.txt

$(BINDIR)/$(1)/env_init.linux: | $(BINDIR)/$(1)/qemu-starter
	env JOVE_DUMP_ENV=1 $(call qemu_softfpu_build_dir,$(1),linux)/qemu-$(1) $(BINDIR)/$(1)/qemu-starter > $$@

$(BINDIR)/$(1)/env_init.win: | $(BINDIR)/$(1)/qemu-starter
	env JOVE_DUMP_ENV=1 $(call qemu_softfpu_build_dir,$(1),win)/qemu-$(1) $(BINDIR)/$(1)/qemu-starter > $$@
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_template,$(t))))

.PHONY: check-helpers
check-helpers: $(foreach t,$(ALL_TARGETS),check-helpers-$(t))

.PHONY: ccopy
ccopy: $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/linux.copy.h) \
       $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/env.copy.h) \
       $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(t)/qemu.tcg.copy.h) \
       $(foreach t,$(ALL_TARGETS),$(BINDIR)/$(HOST_TARGET)/qemu.tcg.copy.$(t).h)

.PHONY: clean-qemu
clean-qemu:
	find $(BINDIR) -name 'env.copy.h' -delete
	find $(BINDIR) -name 'qemu.tcg.copy.*.h' -delete
	find $(BINDIR) -name 'qemu.tcg.copy.h' -delete
	find $(BINDIR) -name 'tcgconstants.h' -delete
	find $(BINDIR) -name 'tcgconstants.*.h' -delete
	find $(BINDIR) -name 'all_helpers.mk' -delete
	find $(BINDIR) -name 'qemu-*.bitcode.cut' -delete
	find $(BINDIR) -name 'env_init*' -delete
	find $(BINDIR) -name 'softfpu-*.o' -delete
	find $(BINDIR) -name 'asm-offsets-*.*' -delete
