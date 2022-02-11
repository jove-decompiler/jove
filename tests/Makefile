# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

LLVM_CC  := $(ROOT_DIR)/../third_party/llvm-project/install/bin/clang
LLVM_DIS := $(ROOT_DIR)/../third_party/llvm-project/install/bin/llvm-dis

#
# build flags
#
CFLAGS := -Wall \
          -fno-stack-protector \
          -fPIC \
          -O2 \
          -g

#
# important directories
#
SRCDIR := src
BINDIR := bin

#
# find tests
#
SRCS  := $(wildcard $(SRCDIR)/*.c)
TESTS := $(patsubst $(SRCDIR)/%.c,%,$(SRCS))
BINS  := $(foreach test,$(TESTS),$(BINDIR)/$(test))
BCS   := $(foreach test,$(TESTS),$(BINDIR)/$(test).bc)
LLS   := $(foreach test,$(TESTS),$(BINDIR)/$(test).ll)
ASMS  := $(foreach test,$(TESTS),$(BINDIR)/$(test).S)

all: $(BINS) $(ASMS)

multi_threaded_LDFLAGS := -pthread
multi_threaded_simple_LDFLAGS := -pthread
complex_num_f_LDFLAGS := -lm
complex_num_d_LDFLAGS := -lm

define test_template
$(BINDIR)/$(1): $(SRCDIR)/$(1).c
	@echo CC $(1)
	@$(LLVM_CC) -o $$@ $(CFLAGS) $$< $($(1)_LDFLAGS) -fuse-ld=lld

$(BINDIR)/$(1).S: $(SRCDIR)/$(1).c
	@echo CC $(1)
	@$(LLVM_CC) -o $$@ $(CFLAGS) -S $$<

$(BINDIR)/$(1).bc: $(SRCDIR)/$(1).c
	@echo BC $(1)
	@$(LLVM_CC) -o $$@ -c -emit-llvm $(CFLAGS) $$<

$(BINDIR)/$(1).ll: $(BINDIR)/$(1).bc
	@echo LL $(1)
	@$(LLVM_DIS) -o $$@ $$<

.PHONY: clean-$(1)
clean-$(1):
	rm -f $(BINDIR)/$(1)
	rm -f $(BINDIR)/$(1).S
	rm -f $(BINDIR)/$(1).bc
	rm -f $(BINDIR)/$(1).ll
endef
$(foreach test,$(TESTS),$(eval $(call test_template,$(test))))

.PHONY: clean
clean: $(foreach test,$(TESTS),clean-$(test))
