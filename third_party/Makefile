# this just obtains the directory this Makefile resides in
THIRD_PARTY_ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

_LLVM_DIR         := $(THIRD_PARTY_ROOT_DIR)/llvm-project
_LLVM_INSTALL_DIR := $(_LLVM_DIR)/install

GCC_TARGET := $(shell gcc -dumpmachine | tr -cd '0-9_a-z-')

ifeq "$(GCC_TARGET)" "x86_64-pc-linux-gnu"
_LLVM_TARGETS_TO_BUILD := X86
else ifeq "$(GCC_TARGET)" "x86_64-linux-gnu"
_LLVM_TARGETS_TO_BUILD := X86
else ifeq "$(GCC_TARGET)" "i686-pc-linux-gnu"
_LLVM_TARGETS_TO_BUILD := X86
else ifeq "$(GCC_TARGET)" "i686-linux-gnu"
_LLVM_TARGETS_TO_BUILD := X86
else ifeq "$(GCC_TARGET)" "aarch64-unknown-linux-gnu"
_LLVM_TARGETS_TO_BUILD := AArch64
else ifeq "$(GCC_TARGET)" "aarch64-linux-gnu"
_LLVM_TARGETS_TO_BUILD := AArch64
else ifeq "$(GCC_TARGET)" "armv7l-unknown-linux-gnueabihf"
_LLVM_TARGETS_TO_BUILD := ARM
else ifeq "$(GCC_TARGET)" "mips64el-linux-gnuabi64"
_LLVM_TARGETS_TO_BUILD := Mips
else ifeq "$(GCC_TARGET)" "mipsel-linux-gnu"
_LLVM_TARGETS_TO_BUILD := Mips
else ifeq "$(GCC_TARGET)" "mips-linux-gnu"
_LLVM_TARGETS_TO_BUILD := Mips
else
$(error "Unknown GCC target $(GCC_TARGET)")
endif

$(info GCC TARGET  $(GCC_TARGET))
$(info LLVM_TARGET $(_LLVM_TARGETS_TO_BUILD))

#BUILD_TYPE := Debug
BUILD_TYPE := Release

.PHONY: nothing
nothing:
	@echo .

#
# -D "CMAKE_PREFIX_PATH=${COMFORT_FUZZ_HOME}/comfort-env/"
# -D "PYTHON_EXECUTABLE=/usr/bin/python"
#


.PHONY: build-llvm
build-llvm:
	cd $(_LLVM_DIR) && \
	rm -rf build && \
	mkdir build && \
	cd build && \
	cmake -G Ninja \
	      -D CMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	      -D "CMAKE_INSTALL_PREFIX=$(_LLVM_INSTALL_DIR)" \
	      -D "LLVM_ENABLE_PROJECTS=compiler-rt;clang;lld" \
	      -D LLVM_ENABLE_RTTI=ON \
	      -D LLVM_ENABLE_ASSERTIONS=OFF \
	      -D COMPILER_RT_USE_BUILTINS_LIBRARY=ON \
	      -D LLVM_ENABLE_EH=ON \
	      -D LLVM_BUILD_DOCS=OFF \
	      -D LLVM_BINUTILS_INCDIR=/usr/include \
	      -D LLVM_ENABLE_BINDINGS=OFF \
	      -D LLVM_ENABLE_PIC=ON \
	      -D LLVM_ENABLE_Z3_SOLVER=ON \
	      -D LLVM_HOST_TRIPLE=$(GCC_TARGET) \
	      -D LLVM_DEFAULT_TARGET_TRIPLE=$(GCC_TARGET) \
	      -D "LLVM_TARGETS_TO_BUILD=X86;AArch64;Mips" \
	      -D LLVM_ENABLE_LTO=OFF \
	      -D LLVM_USE_LINKER=bfd \
	      -D "CMAKE_C_FLAGS=-I /usr/include/tirpc" \
	      -D "CMAKE_CXX_FLAGS=-I /usr/include/tirpc" \
	      -D "CMAKE_EXE_LINKER_FLAGS=-static" \
	      ../llvm \
	&& ninja install
