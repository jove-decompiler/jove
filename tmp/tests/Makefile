# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

#
# build flags
#
CFLAGS := -Weverything \
          -fno-plt \
	  -fno-stack-protector \
          -O3

#
# important directories
#
SRCDIR := $(ROOT_DIR)/src
BINDIR := $(ROOT_DIR)/bin

#
# find tests
#
SRCS  := $(wildcard $(SRCDIR)/*.c)
TESTS := $(patsubst $(SRCDIR)/%.c,%,$(SRCS))
BINS  := $(foreach test,$(TESTS),$(BINDIR)/$(test))
BCS   := $(foreach test,$(TESTS),$(BINDIR)/$(test).bc)
LLS   := $(foreach test,$(TESTS),$(BINDIR)/$(test).ll)

all: $(BINS) $(BCS) $(LLS)

define build_test_template
$(BINDIR)/$(1): $(SRCDIR)/$(1).c
	@echo CC $(1)
	@clang -o $$@ $(CFLAGS) $$<
endef
$(foreach test,$(TESTS),$(eval $(call build_test_template,$(test))))

define build_test_bc_template
$(BINDIR)/$(1).bc: $(SRCDIR)/$(1).c
	@echo BC $(1)
	@clang -o $$@ -c -emit-llvm $(CFLAGS) $$<
endef
$(foreach test,$(TESTS),$(eval $(call build_test_bc_template,$(test))))

define build_test_ll_template
$(BINDIR)/$(1).ll: $(BINDIR)/$(1).bc
	@echo LL $(1)
	@llvm-dis -o $$@ $$<
endef
$(foreach test,$(TESTS),$(eval $(call build_test_ll_template,$(test))))

define clean_test_template
.PHONY: clean-$(1)
clean-$(1):
	rm -f $(BINDIR)/$(1)
	rm -f $(BINDIR)/$(1).bc
	rm -f $(BINDIR)/$(1).ll
endef
$(foreach test,$(TESTS),$(eval $(call clean_test_template,$(test))))

.PHONY: clean
clean: $(foreach test,$(TESTS),clean-$(test))
