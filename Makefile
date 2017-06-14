include config.mk

.PHONY: all_targets
all_targets: $(patsubst %,target_%,$(qemutcg_archs))

define TARGET_TEMPLATE =
bin/$(1):
	mkdir bin/$(1)

.PHONY: target_$(1)
target_$(1): bin/transform-helpers bin/llknife | bin/$(1)
	@$$(MAKE) -C bin/qemu/$(1)-linux-user -f $(ROOT_DIR)/target.mk --include-dir=$(ROOT_DIR) --include-dir=$(qemu_build_dir) --include-dir=$(qemu_build_dir)/$(1)-softmmu SRC_PATH=$(qemu_src_dir) BUILD_DIR=$(qemu_build_dir) _TARGET_NAME=$(1)
endef
$(foreach targ,$(qemutcg_archs),$(eval $(call TARGET_TEMPLATE,$(targ))))

LLVMOCAMLLIBSDIR := /usr/lib/ocaml/llvm

OCAMLLIBNAMES := nums \
                 str \
                 unix

LLVMLIBNAMES  := llvm \
                 llvm_bitreader \
                 llvm_bitwriter \
                 llvm_analysis

CLIBDIRS  := -ccopt -L -ccopt /usr/lib/ocaml

OCAMLLIBS := $(patsubst %,/usr/lib/ocaml/%.cmxa,$(OCAMLLIBNAMES))
LLVMLLIBS := $(patsubst %,$(LLVMOCAMLLIBSDIR)/%.cmxa,$(LLVMLIBNAMES))

.PHONY: configure
configure: bin/llknife
	@rm -f bin/llknife.ml # XXX
	mkdir -p bin
	@for f in $$(find . -type f -iname '*.ml'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $f bin/$$BNM ; \
	  ln -sr $$f bin/$$BNM ; \
	done
	@for f in $$(find . -type f -iname '*.c'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $$f bin/$$BNM ; \
	  ln -sr $$f bin/$$BNM ; \
	done
	@for f in $$(find . -type f -iname '*.cpp'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $$f bin/$$BNM ; \
	  ln -sr $$f bin/$$BNM ; \
	done
	ln -s ../abi/aarch64/arch.callconv bin/aarch64.callconv
	ln -s ../abi/x86_64/sysv.callconv bin/x86_64.callconv
	ln -s ../abi/arm/standard.callconv bin/arm.callconv
	cp -r $(qemu_dir) $(qemu_build_dir)
	mkdir bin/qemuutil
	mkdir bin/qemustub
	cp $(qemu_build_dir)/libqemuutil.a bin/qemuutil/
	cp $(qemu_build_dir)/libqemustub.a bin/qemustub/
	cd bin/qemuutil/ && ar x libqemuutil.a
	cd bin/qemustub/ && ar x libqemustub.a
	rm bin/qemuutil/libqemuutil.a
	rm bin/qemustub/libqemustub.a
	llvm-link -o bin/qemuutil.bc bin/qemuutil/*
	llvm-link -o bin/qemustub.bc bin/qemustub/*
	rm -r bin/qemuutil
	rm -r bin/qemustub
	find $(qemu_build_dir) -type f -name '*.o' -print0 | parallel -q0 bin/llknife --change-fn-def-to-decl-regex '\(cpu_ld.*\)\|\(cpu_st[qlwb]_.*\)\|\(tlb_vaddr_to_host\)' -i
	find $(qemu_build_dir) -type f -name '*.o' -print0 | parallel -q0 bin/llknife --make-external-and-rename-regex 'do_qemu_init_register_types' -i

bin/llknife.ml: tools/llknife.ml
	ln -sf ../tools/llknife.ml $@

bin/llknife: bin/llknife.ml bin/extllvm.cmx bin/extllvm_ocaml.c.o bin/extllvm_ocaml.cpp.o
	@echo OCAML $@
	@ocamlopt -o $@ -absname -g -thread -I /usr/lib/ocaml/llvm -I bin bin/extllvm.cmx bin/extllvm_ocaml.c.o bin/extllvm_ocaml.cpp.o $(CLIBDIRS) $(OCAMLLIBS) $(LLVMLLIBS) $<

bin/extllvm.cmx: lib/extllvm.ml
	@echo OCAML $@
	@ocamlopt -o $@ -c -g -thread -I /usr/lib/ocaml/llvm $<

bin/extllvm_ocaml.c.o: lib/extllvm_ocaml.c
	@echo CLANG $@
	@clang -o $@ -c -I/usr/lib/ocaml $(shell llvm-config --cflags) $<

bin/extllvm_ocaml.cpp.o: lib/extllvm_ocaml.cpp
	@echo CLANG++ $@
	@clang++ -o $@ -c $(shell llvm-config --cxxflags) $<

bin/transform-helpers: bin/transform_helpers.ml bin/extllvm.cmx bin/extllvm_ocaml.c.o bin/extllvm_ocaml.cpp.o
	@echo OCAML $@
	@ocamlopt -o $@ -absname -g -thread -I /usr/lib/ocaml/ocamlgraph -I /usr/lib/ocaml/llvm -I bin bin/extllvm.cmx bin/extllvm_ocaml.c.o bin/extllvm_ocaml.cpp.o $(CLIBDIRS) $(OCAMLLIBS) /usr/lib/ocaml/ocamlgraph/graph.cmxa $(LLVMLLIBS) $<

.PHONY: clean
clean:
	rm -rf bin/*
