include config.mk

.PHONY: all_targets
all_targets: $(patsubst %,target_%,$(qemutcg_archs))

define TARGET_TEMPLATE =
$(build_dir)/$(1):
	mkdir $(build_dir)/$(1)

.PHONY: target_$(1)
target_$(1): $(build_dir)/transform-helpers $(build_dir)/llknife | $(build_dir)/$(1)
	@$$(MAKE) -C $(build_dir)/qemu/$(1)-linux-user -f $(ROOT_DIR)/target.mk --include-dir=$(ROOT_DIR) --include-dir=$(qemu_build_dir) --include-dir=$(qemu_build_dir)/$(1)-softmmu SRC_PATH=$(qemu_src_dir) BUILD_DIR=$(qemu_build_dir) _TARGET_NAME=$(1)
endef
$(foreach targ,$(qemutcg_archs),$(eval $(call TARGET_TEMPLATE,$(targ))))

# -lpixman-1 -lfdt -lm -lgthread-2.0 -pthread -lglib-2.0 -lz -lrt -lutil
#LDFLAGS -Wl,-z,relro -Wl,-z,now -pie -m64 -flto -fno-inline
#LIBS -lpixman-1 -lutil -lnuma -lbluetooth -lncursesw -lvdeplug -luuid -lSDL -lpthread -lX11 -lnettle -lgnutls -lgtk-x11-2.0 -lgdk-x11-2.0 -lpangocairo-1.0 -latk-1.0 -lcairo -lgdk_pixbuf-2.0 -lgio-2.0 -lpangoft2-1.0 -lpango-1.0 -lgobject-2.0 -lglib-2.0 -lfontconfig -lfreetype -lX11 -llzo2 -lsnappy -lseccomp -lfdt -lcacard -lglib-2.0 -lusb-1.0 -lusbredirparser -lm -lgthread-2.0 -pthread -lglib-2.0 -lz -lrt

LLVMLIBSDIR      := $(llvm_dir)/lib
LLVMOCAMLLIBSDIR := $(LLVMLIBSDIR)/ocaml

OCAMLLIBNAMES := nums \
                 str \
                 ocamlgraph/graph

LLVMLIBNAMES  := llvm \
                 llvm_bitreader \
                 llvm_bitwriter \
                 llvm_analysis
#OPAMLIBNAMES  := 

INCLUDES  := -I $(build_dir) \
             -I $(ocaml_dir) \
             -I $(ocaml_dir)/ocamlgraph \
             -I $(LLVMOCAMLLIBSDIR) \
             $(patsubst %,-I %,$(patsubst %/,%,$(dir $(patsubst %,$(opam_libs_dir)/%,$(OPAMLIBNAMES)))))

CLIBDIRS  := -ccopt -L -ccopt $(ocaml_dir) -ccopt -L -ccopt $(LLVMOCAMLLIBSDIR) -ccopt -L -ccopt $(LLVMLIBSDIR)

OCAMLLIBS := $(patsubst %,$(ocaml_dir)/%.cmxa,$(OCAMLLIBNAMES))
LLVMLLIBS := $(patsubst %,$(LLVMOCAMLLIBSDIR)/%.cmxa,$(LLVMLIBNAMES))
OPAMLIBS  := $(patsubst %,$(opam_libs_dir)/%.cmxa,$(OPAMLIBNAMES))

LLCONFIG := $(llvm_dir)/bin/llvm-config
LLCXX    := $(llvm_dir)/bin/clang++
LLCC     := $(llvm_dir)/bin/clang
LLOPT    := $(llvm_dir)/bin/opt
LLLD     := $(llvm_dir)/bin/llvm-link

$(build_dir):
	mkdir $@
	for f in $$(find . -type f -iname '*.ml'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $f $(build_dir)/$$BNM ; \
	  ln -sr $$f $(build_dir)/$$BNM ; \
	done
	for f in $$(find . -type f -iname '*.c'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $$f $(build_dir)/$$BNM ; \
	  ln -sr $$f $(build_dir)/$$BNM ; \
	done
	for f in $$(find . -type f -iname '*.cpp'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $$f $(build_dir)/$$BNM ; \
	  ln -sr $$f $(build_dir)/$$BNM ; \
	done
	ln -s ../abi/aarch64/arch.callconv $(build_dir)/aarch64.callconv
	ln -s ../abi/x86_64/sysv.callconv $(build_dir)/x86_64.callconv
	ln -s ../abi/arm/standard.callconv $(build_dir)/arm.callconv
	cp -r $(qemu_dir) $(qemu_build_dir)
	mkdir $(build_dir)/qemuutil
	mkdir $(build_dir)/qemustub
	cp $(qemu_build_dir)/libqemuutil.a $(build_dir)/qemuutil/
	cp $(qemu_build_dir)/libqemustub.a $(build_dir)/qemustub/
	cd $(build_dir)/qemuutil/ && ar x libqemuutil.a
	cd $(build_dir)/qemustub/ && ar x libqemustub.a
	rm $(build_dir)/qemuutil/libqemuutil.a
	rm $(build_dir)/qemustub/libqemustub.a
	$(llvm_dir)/bin/llvm-link -o $(build_dir)/qemuutil.bc $(build_dir)/qemuutil/*
	$(llvm_dir)/bin/llvm-link -o $(build_dir)/qemustub.bc $(build_dir)/qemustub/*
	rm -r build/qemuutil
	rm -r build/qemustub

$(build_dir)/llknife: $(build_dir)/llknife.ml $(build_dir)/extllvm.cmx $(build_dir)/extllvm_ocaml.c.o $(build_dir)/extllvm_ocaml.cpp.o
	@echo OCAMLC $< $(OCAMLLIBNAMES) $(OPAMLIBNAMES) $(LLVMLIBNAMES)
	@ocamlopt -o $@ -absname -g -thread -ccopt -flto $(INCLUDES) $(build_dir)/extllvm.cmx $(build_dir)/extllvm_ocaml.c.o $(build_dir)/extllvm_ocaml.cpp.o $(CLIBDIRS) $(OCAMLLIBS) $(OPAMLIBS) $(LLVMLLIBS) $<

$(build_dir)/extllvm.cmx: $(build_dir)/extllvm.ml
	@echo OCAMLC $@ $^
	@ocamlopt -c -o $@ -g -thread $(INCLUDES) $<

$(build_dir)/extllvm_ocaml.c.o: $(build_dir)/extllvm_ocaml.c
	@echo LLCC $@ $^
	@$(LLCC) -o $@ -c -I/usr/lib/ocaml $(shell $(LLCONFIG) --cflags) $<

$(build_dir)/extllvm_ocaml.cpp.o: $(build_dir)/extllvm_ocaml.cpp
	@echo LLCXX $@ $^
	@$(LLCXX) -o $@ -c $(shell $(LLCONFIG) --cxxflags) $<

$(build_dir)/transform-helpers: $(build_dir)/transform_helpers.ml $(build_dir)/extllvm.cmx $(build_dir)/extllvm_ocaml.c.o $(build_dir)/extllvm_ocaml.cpp.o
	@echo OCAMLC $< $(OCAMLLIBNAMES) $(OPAMLIBNAMES) $(LLVMLIBNAMES)
	@ocamlopt -o $@ -absname -g -thread -ccopt -flto $(build_dir)/extllvm.cmx $(build_dir)/extllvm_ocaml.c.o $(build_dir)/extllvm_ocaml.cpp.o $(INCLUDES) $(CLIBDIRS) $(OCAMLLIBS) $(OPAMLIBS) $(LLVMLLIBS) $<

.PHONY: configure
configure: $(build_dir) | $(build_dir)/llknife
	find $(qemu_build_dir) -type f -name '*.o' -print0 | parallel -q0 $(build_dir)/llknife --change-fn-def-to-decl-regex '\(cpu_ld.*\)\|\(cpu_st[qlwb]_.*\)\|\(tlb_vaddr_to_host\)' -i
	find $(qemu_build_dir) -type f -name '*.o' -print0 | parallel -q0 $(build_dir)/llknife --make-external-and-rename-regex 'do_qemu_init_register_types' -i

.PHONY: build-tools
build-tools: $(build_dir)/llknife $(build_dir)/transform-helpers

.PHONY: clean
clean:
	rm -rf build
