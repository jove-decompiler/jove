# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

#
# build flags
#
CFLAGS := -Wall \
          -fno-stack-protector \
          -fPIE \
          -Oz \
          -g

LDFLAGS := -pie

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

all: $(BINS) $(BCS) $(LLS) $(ASMS)

define test_template
$(BINDIR)/$(1): $(SRCDIR)/$(1).c
	@echo CC $(1)
	@clang -o $$@ $(CFLAGS) $$< $(LDFLAGS)

$(BINDIR)/$(1).S: $(SRCDIR)/$(1).c
	@echo CC $(1)
	@clang -o $$@ $(CFLAGS) -S $$<

$(BINDIR)/$(1).bc: $(SRCDIR)/$(1).c
	@echo BC $(1)
	@clang -o $$@ -c -emit-llvm $(CFLAGS) $$<

$(BINDIR)/$(1).ll: $(BINDIR)/$(1).bc
	@echo LL $(1)
	@llvm-dis -o $$@ $$<

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
