# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

JOVE_ROOT_DIR := $(ROOT_DIR)/..

include $(JOVE_ROOT_DIR)/targets.mk

LLVM_BIN_DIR := $(JOVE_ROOT_DIR)/llvm-project/build/llvm/bin

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

SINGLE_THREADED_TESTS_TO_SKIP := multi_threaded
MULTI_THREADED_TESTS_TO_SKIP := longjmp

ST_TESTS := $(filter-out $(SINGLE_THREADED_TESTS_TO_SKIP),$(ALL_TESTS))
MT_TESTS := $(filter-out $(MULTI_THREADED_TESTS_TO_SKIP),$(ALL_TESTS))

ST_TESTS := $(filter-out $(TESTS_TO_SKIP),$(ST_TESTS))
MT_TESTS := $(filter-out $(TESTS_TO_SKIP),$(MT_TESTS))

.PHONY: build
build: $(foreach t,$(ALL_TARGETS),build-$(t))

.PHONY: check
check: $(foreach t,$(ALL_TARGETS),check-$(t))

.PHONY: just-update-jove
just-update-jove: $(foreach t,$(ALL_TARGETS),just-update-jove-$(t))

define check_template
.PHONY: build-$(1)
build-$(1): $(foreach test,$(ST_TESTS),$(BINDIR)/$(1)/$(test).exe) \
            $(foreach test,$(ST_TESTS),$(BINDIR)/$(1)/$(test).pic) \
            $(foreach test,$(MT_TESTS),$(BINDIR)/$(1)/$(test).exe) \
            $(foreach test,$(MT_TESTS),$(BINDIR)/$(1)/$(test).pic)

.PHONY: check-$(1)
check-$(1): build-$(1)
	$(ROOT_DIR)/run.py -a $(1) --single-threaded $(ST_TESTS) --multi-threaded $(MT_TESTS)

.PHONY: just-update-jove-$(1)
just-update-jove-$(1):
	$(ROOT_DIR)/run.py -a $(1) --just-update-jove
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call check_template,$(t))))

define target_template
$(BINDIR)/$(1)/%.exe: $(SRCDIR)/%.c
	$(CC) -o $$@ $(CFLAGS) --target=$($(1)_TRIPLE) $$< -fno-pic -no-pie $$(EXTRAFLAGS)

$(BINDIR)/$(1)/%.pic: $(SRCDIR)/%.c
	$(CC) -o $$@ $(CFLAGS) --target=$($(1)_TRIPLE) $$< -fpie -pie $$(EXTRAFLAGS)
endef
$(foreach t,$(ALL_TARGETS),$(eval $(call target_template,$(t))))

.PHONY: clean
clean:
	rm -r $(BINDIR)/*
