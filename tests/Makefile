# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

JOVE_ROOT_DIR := $(ROOT_DIR)/..

include $(JOVE_ROOT_DIR)/config.mk

LLVM_BIN_DIR := $(JOVE_ROOT_DIR)/llvm-project/build/bin

CC := clang-16

#
# build flags
#
CFLAGS := -Wall \
          -fno-stack-protector \
          -O2 \
          -g \
          -fwrapv

EXTRAFLAGS = $(shell awk -v search="/// FLAGS: " 'substr($$0, 1, length(search)) == search { print }' $< | cut -c 12-)

#
# important directories
#
SRCDIR := $(ROOT_DIR)/src
BINDIR := $(ROOT_DIR)/bin

$(foreach t,$(ALL_TARGETS),$(shell mkdir -p $(BINDIR)/$(t)))

#
# find tests
#
SRCS      := $(wildcard $(SRCDIR)/*.c)
ALL_TESTS := $(patsubst $(SRCDIR)/%.c,%,$(SRCS))

# FIXME
TESTS_TO_SKIP := multi_threaded longjmp

TESTS := $(filter-out $(TESTS_TO_SKIP),$(ALL_TESTS))

$(info $(TESTS))

.PHONY: build
build: $(foreach t,$(ALL_TARGETS),build-$(t))

.PHONY: check
check: $(foreach t,$(ALL_TARGETS),check-$(t))

define check_template
.PHONY: build-$(1)
build-$(1): $(foreach test,$(TESTS),$(BINDIR)/$(1)/$(test).exe) \
            $(foreach test,$(TESTS),$(BINDIR)/$(1)/$(test).pic) \
            $(foreach test,$(TESTS),$(BINDIR)/$(1)/$(test).S)

.PHONY: check-$(1)
check-$(1): build-$(1)
	$(ROOT_DIR)/run.py -a $(1) $(TESTS)
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call check_template,$(t))))

define target_template
$(BINDIR)/$(1)/%.exe: $(SRCDIR)/%.c
	$(CC) -o $$@ $(CFLAGS) --target=$($(1)_TRIPLE) $$< -no-pie $$(EXTRAFLAGS)

$(BINDIR)/$(1)/%.pic: $(SRCDIR)/%.c
	$(CC) -o $$@ $(CFLAGS) --target=$($(1)_TRIPLE) $$< -fPIE -pie $$(EXTRAFLAGS)

$(BINDIR)/$(1)/%.S: $(SRCDIR)/%.c
	$(CC) -o $$@ $(CFLAGS) --target=$($(1)_TRIPLE) -S -fverbose-asm $$<
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_template,$(t))))

.PHONY: clean
clean:
	rm -r $(BINDIR)/*
