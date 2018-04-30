CFLAGS := -Wall \
          -Wno-macro-redefined \
          -Wno-shift-count-negative \
          -Wno-initializer-overrides \
          -fPIC -flto -O1 -g

CXXFLAGS := -std=gnu++14 -fno-rtti -fno-exceptions
LDFLAGS := $(shell pkg-config --libs glib-2.0) \
           $(shell llvm-config --ldflags --libs) \
           -lboost_filesystem \
	   -lboost_system

ARCHS := x86_64 \
         aarch64

TOOLS := dump \
         defs \
         constants

tcgtools = $(foreach arch,$(ARCHS),$(arch)-tcg$(1))

all: $(foreach tool,$(TOOLS),$(call tcgtools,$(tool)))

define tcgtool_template
$(1)-tcg$(2): tcg$(2).cpp arch/$(1)/tcg.hpp arch/$(1)/stubs.hpp tcgcommon.cpp Makefile
	clang++ -o $$@ -I arch/$(1) $(CFLAGS) $(CXXFLAGS) $$< $(LDFLAGS)
endef
$(foreach tool,$(TOOLS),$(foreach arch,$(ARCHS),$(eval $(call tcgtool_template,$(arch),$(tool)))))

#
# for extricating QEMU code
#

CLANG_EXTRICATE := ~/clang-extricate
QEMU_SRC_DIR    := ~/qemu
QEMU_BUILD_DIR  := ~/qemu

_SL_TCG_GEN_ADDI_I64 := tcg/tcg-op.c:1175l
_SL_TCG_OPTIMIZE     := tcg/optimize.c:592l
_SL_TCG_OP_DEFS      := tcg/tcg-common.c:35l
_SL_TB_GEN_CODE      := accel/tcg/translate-all.c:1247l
_SL_TRANSLATOR_LOOP  := accel/tcg/translator.c:36l
_SL_PSTRCPY          := util/cutils.c:43l

COMMON_SOURCE_LOCATIONS := $(_SL_TCG_GEN_ADDI_I64) \
                           $(_SL_TCG_OPTIMIZE) \
                           $(_SL_TCG_OP_DEFS) \
                           $(_SL_TB_GEN_CODE) \
                           $(_SL_TRANSLATOR_LOOP) \
                           $(_SL_PSTRCPY)

_SL_X86_64_TCG_CONTEXT_INIT := tcg/tcg.c:2070l
_SL_X86_64_TCG_FUNC_START   := tcg/tcg.c:2256l
_SL_X86_64_TCG_GEN_CODE     := tcg/tcg.c:4633l

_SL_X86_64_GEN_INTERMEDIATE_CODE  := target/i386/translate.c:8573l
_SL_X86_64_TCG_X86_INIT           := target/i386/translate.c:8328l
# _SL_X86_64_TCG_GEN_GVEC_NOT       := tcg/tcg-op-gvec.c:1357l
# _SL_X86_64_TCG_GEN_LD_VEC         := tcg/tcg-op-vec.c:209l

x86_64_SOURCE_LOCATIONS := $(_SL_X86_64_TCG_CONTEXT_INIT) \
                           $(_SL_X86_64_TCG_FUNC_START) \
                           $(_SL_X86_64_TCG_GEN_CODE) \
                           $(_SL_X86_64_GEN_INTERMEDIATE_CODE) \
                           $(_SL_X86_64_TCG_X86_INIT)

#                           $(_SL_X86_64_TCG_GEN_GVEC_NOT) \
#                           $(_SL_X86_64_TCG_GEN_LD_VEC)

_SL_AARCH64_TCG_CONTEXT_INIT := tcg/tcg.c:1808l
_SL_AARCH64_TCG_FUNC_START   := tcg/tcg.c:1994l
_SL_AARCH64_TCG_GEN_CODE     := tcg/tcg.c:4371l

_SL_AARCH64_GEN_INTERMEDIATE_CODE := target/arm/translate.c:12732l
_SL_AARCH64_TRANSLATOR_OPS        := target/arm/translate-a64.c:13448l
_SL_AARCH64_TRANSLATE_INIT        := target/arm/translate.c:85l
_SL_AARCH64_TCG_GEN_GVEC_NOT      := tcg/tcg-op-gvec.c:1357l
_SL_AARCH64_TCG_GEN_LD_VEC        := tcg/tcg-op-vec.c:209l

aarch64_SOURCE_LOCATIONS := $(_SL_AARCH64_TCG_CONTEXT_INIT) \
                            $(_SL_AARCH64_TCG_FUNC_START) \
                            $(_SL_AARCH64_TCG_GEN_CODE) \
                            $(_SL_AARCH64_GEN_INTERMEDIATE_CODE) \
                            $(_SL_AARCH64_TRANSLATOR_OPS) \
                            $(_SL_AARCH64_TRANSLATE_INIT) \
                            $(_SL_AARCH64_TCG_GEN_GVEC_NOT) \
                            $(_SL_AARCH64_TCG_GEN_LD_VEC)

define gen_template
.PHONY: gen-$(1)
gen-$(1):
	$(CLANG_EXTRICATE)/extract/bin/carbon-extract --src $(QEMU_SRC_DIR) --bin $(QEMU_BUILD_DIR) $(COMMON_SOURCE_LOCATIONS) $($(1)_SOURCE_LOCATIONS) > arch/$(1)/tcg.hpp
endef
$(foreach arch,$(ARCHS),$(eval $(call gen_template,$(arch))))

.PHONY: clean
clean:
	rm -f $(foreach tool,$(TOOLS),$(call tcgtools,$(tool)))

#
# qemu configure command
#
# ./configure --target-list=x86_64-linux-user --cc=clang --host-cc=clang --cxx=clang++ --objcc=clang --disable-tcg-interpreter --disable-sdl --disable-gtk --disable-xen --disable-bluez --disable-kvm --disable-guest-agent --disable-vnc --disable-libssh2 --disable-jemalloc --disable-tcmalloc --disable-vhost-user --disable-opengl --disable-glusterfs --disable-gnutls --disable-nettle --disable-gcrypt --disable-curses --disable-libnfs --disable-libusb --disable-lzo --disable-bzip2 --disable-vhost-vsock --disable-smartcard --disable-usb-redir --disable-spice --disable-vhost-net --disable-snappy --disable-seccomp --disable-vhost-scsi --disable-virglrenderer --disable-vde --disable-rbd --disable-live-block-migration --disable-tools --disable-tpm --disable-numa --disable-cap-ng --disable-replication --disable-vte --disable-qom-cast-debug --disable-tpm --disable-xfsctl --disable-linux-aio --disable-attr --disable-coroutine-pool --disable-hax --enable-trace-backends=nop --disable-libxml2 --disable-vhost-crypto --extra-cflags="-Xclang -load -Xclang $HOME/clang-extricate/collect/bin/carbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd) -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
#
