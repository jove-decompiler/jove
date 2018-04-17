CFLAGS := -Wall -Wno-macro-redefined -fPIC -flto -O3 -g
CXXFLAGS := -std=gnu++14 -fno-rtti -fno-exceptions
LDFLAGS := $(shell pkg-config --libs glib-2.0) \
           $(shell llvm-config --ldflags --libs) \
           -lboost_filesystem \
	   -lboost_system

ARCHS := x86_64 \
         aarch64

#ARCHS := aarch64

all: $(foreach arch,$(ARCHS),$(arch)-tcgdump)

define tcgdump_template
$(1)-tcgdump: tcgdump.cpp arch/$(1)/tcg.hpp arch/$(1)/stubs.hpp Makefile
	clang++ -o $$@ -I arch/$(1) $(CFLAGS) $(CXXFLAGS) $$< $(LDFLAGS)
endef
$(foreach arch,$(ARCHS),$(eval $(call tcgdump_template,$(arch))))

CLANG_EXTRICATE := ~/clang-extricate
QEMU_SRC_DIR    := ~/qemu
QEMU_BUILD_DIR  := ~/qemu

# functions:
#   tcg_context_init
#   tcg_func_start
#   tcg_gen_code
#   tcg_gen_addi_i64
#   tcg_optimize
#   tcg_op_defs
#   tb_gen_code
#   translator_loop
#
# on x86_64:
#   gen_intermediate_code
#
# ./configure --target-list=x86_64-linux-user --cc=clang --host-cc=clang --cxx=clang++ --objcc=clang --disable-tcg-interpreter --disable-sdl --disable-gtk --disable-xen --disable-bluez --disable-kvm --disable-guest-agent --disable-vnc --disable-libssh2 --disable-jemalloc --disable-tcmalloc --disable-vhost-user --disable-opengl --disable-glusterfs --disable-gnutls --disable-nettle --disable-gcrypt --disable-curses --disable-libnfs --disable-libusb --disable-lzo --disable-bzip2 --disable-vhost-vsock --disable-smartcard --disable-usb-redir --disable-spice --disable-vhost-net --disable-snappy --disable-seccomp --disable-vhost-scsi --disable-capstone --disable-virglrenderer --disable-vde --disable-rbd --disable-live-block-migration --disable-tools --disable-tpm --disable-numa --disable-cap-ng --disable-replication --disable-vte --disable-qom-cast-debug --disable-tpm --disable-xfsctl --disable-linux-aio --disable-attr --disable-coroutine-pool --disable-hax --enable-trace-backends=nop --extra-cflags="-Xclang -load -Xclang $HOME/clang-extricate/collect/bin/carbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd) -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
#
# on aarch64:
#   gen_intermediate_code
#   aarch64_translator_ops
#
# ./configure --target-list=aarch64-linux-user --cc=clang --host-cc=clang --cxx=clang++ --objcc=clang --disable-tcg-interpreter --disable-sdl --disable-gtk --disable-xen --disable-bluez --disable-kvm --disable-guest-agent --disable-vnc --disable-libssh2 --disable-jemalloc --disable-tcmalloc --disable-vhost-user --disable-opengl --disable-glusterfs --disable-gnutls --disable-nettle --disable-gcrypt --disable-curses --disable-libnfs --disable-libusb --disable-lzo --disable-bzip2 --disable-vhost-vsock --disable-smartcard --disable-usb-redir --disable-spice --disable-vhost-net --disable-snappy --disable-seccomp --disable-vhost-scsi --disable-capstone --disable-virglrenderer --disable-vde --disable-rbd --disable-live-block-migration --disable-tools --disable-tpm --disable-numa --disable-cap-ng --disable-replication --disable-vte --disable-qom-cast-debug --disable-tpm --disable-xfsctl --disable-linux-aio --disable-attr --disable-coroutine-pool --disable-hax --enable-trace-backends=nop --extra-cflags="-Xclang -load -Xclang $HOME/clang-extricate/collect/bin/carbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd) -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
#

.PHONY: gen-x86_64
gen-x86_64:
	$(CLANG_EXTRICATE)/extract/bin/carbon-extract --src $(QEMU_SRC_DIR) --bin $(QEMU_BUILD_DIR) tcg/tcg.c:1928l tcg/tcg.c:2114l tcg/tcg.c:4430l tcg/tcg-op.c:1193l tcg/optimize.c:604l tcg/tcg-common.c:35l accel/tcg/translate-all.c:1248l accel/tcg/translator.c:36l target/i386/translate.c:8571l > arch/x86_64/tcg.hpp

.PHONY: gen-aarch64
gen-aarch64:
	$(CLANG_EXTRICATE)/extract/bin/carbon-extract --src $(QEMU_SRC_DIR) --bin $(QEMU_BUILD_DIR) tcg/tcg.c:1575l tcg/tcg.c:1761l tcg/tcg.c:4077l tcg/tcg-op.c:1193l tcg/optimize.c:604l tcg/tcg-common.c:35l target/arm/translate-a64.c:11437l target/arm/translate.c:12441l accel/tcg/translate-all.c:1248l accel/tcg/translator.c:36l > arch/aarch64/tcg.hpp

.PHONY: clean
clean:
	rm -f $(foreach arch,$(ARCHS),$(arch)-tcgdump)
