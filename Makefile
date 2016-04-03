include config.mk

.PHONY: all_targets
all_targets: $(patsubst %,target_%,$(qemutcg_archs))

define TARGET_TEMPLATE =
.PHONY: target_$(1)
target_$(1):
	@$$(MAKE) -C $(build_dir)/qemu/$(1)-linux-user -f $(ROOT_DIR)/target.mk --include-dir=$(ROOT_DIR) --include-dir=$(qemu_build_dir) --include-dir=$(qemu_build_dir)/$(1)-softmmu SRC_PATH=$(qemu_src_dir) BUILD_DIR=$(qemu_build_dir) _TARGET_NAME=$(1)
endef
$(foreach targ,$(qemutcg_archs),$(eval $(call TARGET_TEMPLATE,$(targ))))

# -lpixman-1 -lfdt -lm -lgthread-2.0 -pthread -lglib-2.0 -lz -lrt -lutil
#LDFLAGS -Wl,-z,relro -Wl,-z,now -pie -m64 -flto -fno-inline
#LIBS -lpixman-1 -lutil -lnuma -lbluetooth -lncursesw -lvdeplug -luuid -lSDL -lpthread -lX11 -lnettle -lgnutls -lgtk-x11-2.0 -lgdk-x11-2.0 -lpangocairo-1.0 -latk-1.0 -lcairo -lgdk_pixbuf-2.0 -lgio-2.0 -lpangoft2-1.0 -lpango-1.0 -lgobject-2.0 -lglib-2.0 -lfontconfig -lfreetype -lX11 -llzo2 -lsnappy -lseccomp -lfdt -lcacard -lglib-2.0 -lusb-1.0 -lusbredirparser -lm -lgthread-2.0 -pthread -lglib-2.0 -lz -lrt

LLVMLIBSDIR  := $(llvm_nonflto_dir)/lib/ocaml

OCAMLLIBNAMES := nums \
                 str
LLVMLIBNAMES  := llvm llvm_bitreader llvm_bitwriter llvm_analysis
OPAMLIBNAMES  := batteries/batteries \
                 zarith/zarith \
                 stdint/stdint

INCLUDES     := -I $(ocaml_dir) \
                -I $(LLVMLIBSDIR) \
				$(patsubst %,-I %,$(patsubst %/,%,$(dir $(patsubst %,$(opam_libs_dir)/%,$(OPAMLIBNAMES)))))

CLIBDIRS     := -ccopt -L -ccopt $(ocaml_dir) -ccopt -L -ccopt $(LLVMLIBSDIR)

OCAMLLIBS    := $(patsubst %,$(ocaml_dir)/%.cmxa,$(OCAMLLIBNAMES))
LLVMLLIBS    := $(patsubst %,$(LLVMLIBSDIR)/%.cmxa,$(LLVMLIBNAMES))
OPAMLIBS     := $(patsubst %,$(opam_libs_dir)/%.cmxa,$(OPAMLIBNAMES))

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

$(build_dir)/llknife: $(build_dir)/llknife.ml
	@echo OCAMLC $< $(OCAMLLIBNAMES) $(OPAMLIBNAMES) $(LLVMLIBNAMES)
	ocamlopt -o $@ -absname -g -thread -ccopt -flto $(INCLUDES) $(CLIBDIRS) $(OCAMLLIBS) $(OPAMLIBS) $(LLVMLLIBS) $<

$(build_dir)/transform-helpers: $(build_dir)/transform_helpers.ml | $(build_dir)
	@echo OCAMLC $< $(OCAMLLIBNAMES) $(OPAMLIBNAMES) $(LLVMLIBNAMES)
	ocamlopt -o $@ -absname -g -thread -ccopt -flto $(INCLUDES) $(CLIBDIRS) $(OCAMLLIBS) $(OPAMLIBS) $(LLVMLLIBS) $<

.PHONY: configure
configure: $(build_dir) | $(build_dir)/llknife
	for bc in $$(find $(qemu_build_dir) -type f -name '*.o') ; do \
	  echo llknife $${bc} ; \
	  $(build_dir)/llknife -o $${bc} -i $${bc} --change-fn-def-to-decl-regex '\(cpu_ld.*\)\|\(cpu_st[qlwb]_.*\)\|\(tlb_vaddr_to_host\)' ; \
	done
	for bc in $$(find $(qemu_build_dir) -type f -name '*.o') ; do \
	  echo llknife $${bc} ; \
	  $(build_dir)/llknife -o $${bc} -i $${bc} --make-external-and-rename-regex 'do_qemu_init_register_types' ; \
	done

.PHONY: build-tools
build-tools: $(build_dir)/llknife $(build_dir)/transform-helpers

.PHONY: clean
clean:
	rm -rf build
