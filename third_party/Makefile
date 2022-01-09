# this just obtains the directory this Makefile resides in
THIRD_PARTY_ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

_LLVM_DIR                := $(THIRD_PARTY_ROOT_DIR)/llvm-project

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
	rm -rf static_build static_install && \
	mkdir static_build && \
	cd static_build && \
	cp $(_LLVM_DIR)/llvm/cmake/config-ix.cmake config-ix.cmake.bak && \
	sed -i '160d;161d;162d;163d;164d;165d;166d;167d;168d;169d;170d' $(_LLVM_DIR)/llvm/cmake/config-ix.cmake && \
	cmake -G Ninja \
	      -D CMAKE_BUILD_TYPE=Release \
	      -D LLVM_ENABLE_ASSERTIONS=OFF \
	      -D "CMAKE_INSTALL_PREFIX=$(_LLVM_DIR)/static_install" \
	      -D "LLVM_ENABLE_PROJECTS=llvm;lld" \
	      -D "LLVM_TARGETS_TO_BUILD=X86;AArch64;Mips" \
	      -D CMAKE_C_COMPILER=$(shell which clang-13) \
	      -D CMAKE_CXX_COMPILER=$(shell which clang++-13) \
	      -D LLVM_ENABLE_LIBCXX=ON \
	      -D LLVM_USE_LINKER=lld \
	      -D BUILD_SHARED_LIBS=OFF \
	      -D LLVM_BUILD_LLVM_DYLIB=OFF \
	      -D LLVM_LINK_LLVM_DYLIB=OFF \
	      -D "CMAKE_EXE_LINKER_FLAGS=-static" \
	      ../llvm \
	&& ninja install && \
	mv config-ix.cmake.bak $(_LLVM_DIR)/llvm/cmake/config-ix.cmake && \
	cd .. && \
	rm -rf build install && \
	mkdir build && \
	cd build && \
	cmake -G Ninja \
	      -D CMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	      -D "CMAKE_INSTALL_PREFIX=$(_LLVM_DIR)/install" \
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
	      ../llvm \
	&& ninja install
