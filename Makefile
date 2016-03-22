include config.mk

SOS      := $(patsubst %,$(build_dir)/lib%2llvm.so,$(qemutcg_archs))
EXAMPLES := $(patsubst examples/%.cpp,$(build_dir)/%,$(wildcard examples/*.cpp))

all: $(SOS) $(EXAMPLES)

define TARGET_template =
$(build_dir)/lib$(1)2llvm.so: $(build_dir)/qemutcg.c $(build_dir)/qemustub.weak.bc $(build_dir)/qemuutil.weak.bc
	@$$(MAKE) -C $(build_dir)/qemu/$(1)-softmmu -f $(ROOT_DIR)/target.mk --include-dir=$(ROOT_DIR) --include-dir=$(qemu_build_dir) --include-dir=$(qemu_build_dir)/$(1)-softmmu SRC_PATH=$(qemu_src_dir) BUILD_DIR=$(qemu_build_dir) _TARGET_NAME=$(1)
endef

$(foreach targ,$(qemutcg_archs),$(eval $(call TARGET_template,$(targ))))

LLVMLIBSDIR  := $(llvm_build_dir)/lib/ocaml

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

$(build_dir)/llknife: $(build_dir)/llknife.ml
	@echo OCAMLC $< $(OCAMLLIBNAMES) $(OPAMLIBNAMES) $(LLVMLIBNAMES)
	@ocamlopt -o $@ -absname -g -thread $(INCLUDES) $(CLIBDIRS) $(OCAMLLIBS) $(OPAMLIBS) $(LLVMLLIBS) $<

$(build_dir)/qemustub.weak.bc: $(build_dir)/llknife
	$(build_dir)/llknife --make-defined-globals-weak -i $(build_dir)/qemustub.bc -o $@

$(build_dir)/qemuutil.weak.bc: $(build_dir)/llknife
	$(build_dir)/llknife --make-defined-globals-weak -i $(build_dir)/qemuutil.bc -o $@

$(build_dir)/%: examples/%.cpp
	@echo CC $(notdir $@ $<)
	@$(llvm_build_dir)/bin/clang++ -o $@ -ldl -lboost_filesystem -lboost_system -O3 $<

.PHONY: configure
configure:
	if [ -d "build" ]; then rm -rf build/* ; fi
	mkdir -p $(patsubst %,build/qemu/%-softmmu,$(qemutcg_archs))
	for f in $$(find . -type f -iname '*.ml'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $f build/$$BNM ; \
	  ln -sr $$f build/$$BNM ; \
	done
	for f in $$(find . -type f -iname '*.c'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $$f build/$$BNM ; \
	  ln -sr $$f build/$$BNM ; \
	done
	for f in $$(find . -type f -iname '*.cpp'); do \
	  BNM=$$(basename $$f) ; \
	  echo ln -sr $$f build/$$BNM ; \
	  ln -sr $$f build/$$BNM ; \
	done
	mkdir build/qemuutil
	mkdir build/qemustub
	cp $(qemu_build_dir)/libqemuutil.a build/qemuutil/
	cp $(qemu_build_dir)/libqemustub.a build/qemustub/
	cd build/qemuutil/ && ar x libqemuutil.a
	cd build/qemustub/ && ar x libqemustub.a
	rm build/qemuutil/libqemuutil.a
	rm build/qemustub/libqemustub.a
	$(llvm_build_dir)/bin/llvm-link -o build/qemuutil.bc build/qemuutil/*
	$(llvm_build_dir)/bin/llvm-link -o build/qemustub.bc build/qemustub/*
	rm -r build/qemuutil
	rm -r build/qemustub

.PHONY: clean
clean:
	rm -rf build

.PHONY: tidy
tidy:
	find . -not -regex ".*.git.*" -type d -empty -print
