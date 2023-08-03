# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

JOVE_ROOT_DIR := $(ROOT_DIR)/..

include $(JOVE_ROOT_DIR)/config.mk

LLVM_BIN_DIR := $(JOVE_ROOT_DIR)/llvm-project/build/bin

LLVM_DIS := $(LLVM_BIN_DIR)/llvm-dis
LLVM_CC  := $(LLVM_BIN_DIR)/clang
LLVM_CXX := $(LLVM_BIN_DIR)/clang++
LLVM_OPT := $(LLVM_BIN_DIR)/opt

#
# build flags
#
CFLAGS := -Wall \
          -fno-stack-protector \
          -O2 \
          -g

#
# important directories
#
SRCDIR := $(ROOT_DIR)/src
BINDIR := $(ROOT_DIR)/bin

$(foreach t,$(ALL_TARGETS),$(shell mkdir -p $(BINDIR)/$(t)))

#
# find tests
#
SRCS  := $(wildcard $(SRCDIR)/*.c)
TESTS := $(patsubst $(SRCDIR)/%.c,%,$(SRCS))

.PHONY: check
check: $(foreach t,$(ALL_TARGETS),check-$(t))

multi_threaded_LDFLAGS := -pthread
multi_threaded_simple_LDFLAGS := -pthread
complex_num_f_LDFLAGS := -lm
complex_num_d_LDFLAGS := -lm

define test_template
$(BINDIR)/$(2)/$(1).exe: $(SRCDIR)/$(1).c
	@echo CC $(1)
	clang-15 -o $$@ $(CFLAGS) --target=$($(2)_TRIPLE) $$< $($(1)_LDFLAGS) -fuse-ld=lld -no-pie

$(BINDIR)/$(2)/$(1).pic: $(SRCDIR)/$(1).c
	@echo CC $(1)
	clang-15 -o $$@ $(CFLAGS) --target=$($(2)_TRIPLE) $$< $($(1)_LDFLAGS) -fuse-ld=lld -fPIE -pie

$(BINDIR)/$(2)/$(1).S: $(SRCDIR)/$(1).c
	@echo CC $(1)
	clang-15 -o $$@ $(CFLAGS) --target=$($(2)_TRIPLE) -S -fverbose-asm $$<
endef
$(foreach t,$(ALL_TARGETS),$(foreach test,$(TESTS),$(eval $(call test_template,$(test),$(t)))))

define check_template
.PHONY: check-$(1)
check-$(1): $(foreach test,$(TESTS),$(BINDIR)/$(1)/$(test).exe) \
            $(foreach test,$(TESTS),$(BINDIR)/$(1)/$(test).pic) \
            $(foreach test,$(TESTS),$(BINDIR)/$(1)/$(test).S)
	@echo CHECK $(1)
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call check_template,$(t))))

.PHONY: clean
clean:
	rm -r $(BINDIR)/*
