# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

include gmsl

JOVE_ROOT_DIR := $(ROOT_DIR)/..

include $(JOVE_ROOT_DIR)/targets.mk

LLVM_BIN_DIR := $(JOVE_ROOT_DIR)/llvm-project/build/llvm/bin

CC := clang-19

#
# build flags
#
CFLAGS := -Wall \
          -fno-stack-protector \
          -O2 \
          -g \
          -fwrapv

EXTRAFLAGS = $(shell awk -v search="/// FLAGS: " 'substr($$0, 1, length(search)) == search { print }' $< | cut -c 12-)

# disable built-in rules
.SUFFIXES:

.PHONY: build
build: $(foreach p,$(PLATFORMS),build-$(p))

.PHONY: check
check: $(foreach p,$(PLATFORMS),check-$(p))

.PHONY: clean
clean: $(foreach p,$(PLATFORMS),clean-$(p))

define template_platform
.PHONY: build-$(1)
build-$(1): $(foreach t,$(ALL_$(call uc,$(1))_TARGETS),build-$(1)-$(t))

.PHONY: check-$(1)
check-$(1): $(foreach t,$(ALL_$(call uc,$(1))_TARGETS),check-$(1)-$(t)-remote) \
            $(foreach t,$(ALL_$(call uc,$(1))_TARGETS),check-$(1)-$(t)-local)

.PHONY: clean-$(1)
clean-$(1): $(foreach t,$(ALL_$(call uc,$(1))_TARGETS),clean-$(1)-$(t))

.PHONY: just-update-jove-$(1)
just-update-jove-$(1): $(foreach t,$(ALL_$(call uc,$(1))_TARGETS),just-update-jove-$(1)-$(t))
endef
$(foreach p,$(PLATFORMS),$(eval $(call template_platform,$(p))))

define template_platform_clean
.PHONY: clean-$(1)-$(2)
clean-$(1)-$(2):
	rm -rf $(ROOT_DIR)/$(1)/bin/$(2)
endef
$(foreach p,$(PLATFORMS),$(foreach t,$(ALL_$(call uc,$p)_TARGETS),$(eval $(call template_platform_clean,$(p),$(t)))))

define template_platform_just_update
.PHONY: just-update-jove-$(1)-$(2)
just-update-jove-$(1)-$(2):
	-$(ROOT_DIR)/run.py -a $(2) -p $(1) --just-update-jove
endef
$(foreach p,$(PLATFORMS),$(foreach t,$(ALL_$(call uc,$p)_TARGETS),$(eval $(call template_platform_just_update,$(p),$(t)))))

define template_linux

SINGLE_THREADED_TESTS_TO_SKIP := multi_threaded

# it's tricky to run jove loop on a program which calls `setjmp(3)` without
# performing some dynamic analysis first, and we can't assume that we can run
# `jove bootstrap` locally.
LOCAL_TESTS_TO_SKIP := longjmp

# FIXME
MULTI_THREADED_TESTS_TO_SKIP := longjmp

SRCDIR := $(ROOT_DIR)/linux/src
BINDIR := $(ROOT_DIR)/linux/bin

$$(shell mkdir -p $$(BINDIR)/$(1))

#
# find tests
#
SRCS      := $$(wildcard $$(SRCDIR)/*.c)
ALL_TESTS := $$(patsubst $$(SRCDIR)/%.c,%,$$(SRCS))

ST_LOCAL_TESTS := $$(filter-out $$(LOCAL_TESTS_TO_SKIP),$$(filter-out $$(SINGLE_THREADED_TESTS_TO_SKIP),$$(ALL_TESTS)))
MT_LOCAL_TESTS := $$(filter-out $$(LOCAL_TESTS_TO_SKIP),$$(filter-out $$(MULTI_THREADED_TESTS_TO_SKIP),$$(ALL_TESTS)))

ST_REMOTE_TESTS := $$(filter-out $$(SINGLE_THREADED_TESTS_TO_SKIP),$$(ALL_TESTS))
MT_REMOTE_TESTS := $$(filter-out $$(MULTI_THREADED_TESTS_TO_SKIP),$$(ALL_TESTS))

.PHONY: build-linux-$(1)
build-linux-$(1): $$(foreach test,$$(ALL_TESTS),$$(BINDIR)/$(1)/$$(test).exe) \
                  $$(foreach test,$$(ALL_TESTS),$$(BINDIR)/$(1)/$$(test).pic)

$(shell mkdir -p .t)
$$(file > .t/linux.tests.$(1).st.local,$$(ST_LOCAL_TESTS))
$$(file > .t/linux.tests.$(1).st.remote,$$(ST_REMOTE_TESTS))
$$(file > .t/linux.tests.$(1).mt.local,$$(MT_LOCAL_TESTS))
$$(file > .t/linux.tests.$(1).mt.remote,$$(MT_REMOTE_TESTS))

.PHONY: check-linux-$(1)-remote
check-linux-$(1)-remote: build-linux-$(1)
	$(ROOT_DIR)/run.py -a $(1) -p linux \
                           --remote \
                           --single-threaded $$(shell cat $(ROOT_DIR)/.t/linux.tests.$(1).st.remote) \
                            --multi-threaded $$(shell cat $(ROOT_DIR)/.t/linux.tests.$(1).mt.remote)

.PHONY: check-linux-$(1)-local
check-linux-$(1)-local: build-linux-$(1)
	$(ROOT_DIR)/run.py -a $(1) -p linux \
                           --local \
                           --single-threaded $$(shell cat $(ROOT_DIR)/.t/linux.tests.$(1).st.local) \
                            --multi-threaded $$(shell cat $(ROOT_DIR)/.t/linux.tests.$(1).mt.local)

$$(BINDIR)/$(1)/%.exe: $$(SRCDIR)/%.c
	$(CC) -o $$@ $(CFLAGS) --target=$($(1)_TRIPLE) $$< -fno-pic -no-pie $$(EXTRAFLAGS)

$$(BINDIR)/$(1)/%.pic: $$(SRCDIR)/%.c
	$(CC) -o $$@ $(CFLAGS) --target=$($(1)_TRIPLE) $$< -fpie -pie $$(EXTRAFLAGS)

undefine SRCDIR
undefine BINDIR
undefine SRCS
undefine ALL_TESTS
undefine SINGLE_THREADED_TESTS_TO_SKIP
undefine MULTI_THREADED_TESTS_TO_SKIP
undefine ST_TESTS
undefine MT_TESTS

endef
$(foreach t,$(ALL_LINUX_TARGETS),$(eval $(call template_linux,$(t))))

define template_win

SRCDIR := $(ROOT_DIR)/win/src
BINDIR := $(ROOT_DIR)/win/bin

$$(shell mkdir -p $$(BINDIR)/$(1))

#
# find tests
#
SRCS      := $$(wildcard $$(SRCDIR)/*.c)
ALL_TESTS := $$(patsubst $$(SRCDIR)/%.c,%,$$(SRCS))

PREBUILTS := $$(wildcard $$(BINDIR)/$(1)/*.EXE)
PREBUILTS_NAMES := $$(basename $$(notdir $$(PREBUILTS)))
PREBUILTS_ONLY  := $$(filter-out $$(ALL_TESTS),$$(PREBUILTS_NAMES))

SINGLE_THREADED_TESTS_TO_SKIP :=
MULTI_THREADED_TESTS_TO_SKIP :=

ST_TESTS := $$(filter-out $$(SINGLE_THREADED_TESTS_TO_SKIP),$$(ALL_TESTS))
MT_TESTS := $$(filter-out $$(MULTI_THREADED_TESTS_TO_SKIP),$$(ALL_TESTS))

ST_TESTS += $$(filter-out $$(SINGLE_THREADED_TESTS_TO_SKIP),$$(PREBUILTS_ONLY))
MT_TESTS += $$(filter-out $$(MULTI_THREADED_TESTS_TO_SKIP),$$(PREBUILTS_ONLY))

.PHONY: build-win-$(1)
build-win-$(1): $$(foreach test,$$(ALL_TESTS),$$(BINDIR)/$(1)/$$(test).EXE) \
                $$(foreach test,$$(ALL_TESTS),$$(BINDIR)/$(1)/$$(test).PIC)

$(shell mkdir -p .t)
$$(file > .t/win.tests.$(1).st,$$(ST_TESTS))
$$(file > .t/win.tests.$(1).mt,$$(MT_TESTS))

.PHONY: check-win-$(1)-remote
check-win-$(1)-remote: build-win-$(1)
	$(ROOT_DIR)/run.py -a $(1) -p win \
                           --remote \
                           --single-threaded $$(shell cat $(ROOT_DIR)/.t/win.tests.$(1).st) \
                            --multi-threaded $$(shell cat $(ROOT_DIR)/.t/win.tests.$(1).mt)

.PHONY: check-win-$(1)-local
check-win-$(1)-local: build-win-$(1)
	$(ROOT_DIR)/run.py -a $(1) -p win \
                           --local \
                           --single-threaded $$(shell cat $(ROOT_DIR)/.t/win.tests.$(1).st) \
                            --multi-threaded $$(shell cat $(ROOT_DIR)/.t/win.tests.$(1).mt)

$$(BINDIR)/$(1)/%.EXE: $$(SRCDIR)/%.c
	$(WIN_$(1)_CC) -o $$@ $(CFLAGS) $$< -fno-pic -no-pie

$$(BINDIR)/$(1)/%.PIC: $$(SRCDIR)/%.c
	$(WIN_$(1)_CC) -o $$@ $(CFLAGS) $$< -fpie -pie

undefine SRCDIR
undefine BINDIR
undefine SRCS
undefine ALL_TESTS
undefine SINGLE_THREADED_TESTS_TO_SKIP
undefine MULTI_THREADED_TESTS_TO_SKIP
undefine ST_TESTS
undefine MT_TESTS

endef
$(foreach t,$(ALL_WIN_TARGETS),$(eval $(call template_win,$(t))))
