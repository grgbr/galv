################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

test-cflags  := -DGALV_VERSION_STRING="\"$(VERSION)\"" $(common-cflags)

# Use -whole-archive to enforce the linker to scan builtin.a static library
# entirely so that symbols in utest.o may override existing strong symbols
# defined into other compilation units.
# This is required since we want stroll_assert_fail() defined into utest.c to
# override stroll_assert_fail() defined into libstroll.so for assertions testing
# purposes.
utest-ldflags := \
	$(test-cflags) \
	-L $(BUILDDIR)/../lib \
	$(EXTRA_LDFLAGS) \
	-Wl,-z,start-stop-visibility=hidden \
	-Wl,-whole-archive $(BUILDDIR)/builtin_utest.a -Wl,-no-whole-archive \
	-lgalv

ifneq ($(filter y,$(CONFIG_GALV_ASSERT_API) $(CONFIG_GALV_ASSERT_INTERN)),)
test-cflags   := $(filter-out -DNDEBUG,$(test-cflags))
utest-ldflags := $(filter-out -DNDEBUG,$(utest-ldflags))
endif # ($(filter y,$(CONFIG_GALV_ASSERT_API) $(CONFIG_GALV_ASSERT_INTERN)),)

builtins               := builtin_utest.a
builtin_utest.a-objs   := echosvc.o ncsvc.o utest.o $(config-obj)
builtin_utest.a-cflags := $(test-cflags)

checkbins              := galv-utest
galv-utest-objs        += $(call kconf_enabled,GALV_UNIX_CONN,unix.o)
galv-utest-cflags      := $(test-cflags)
galv-utest-ldflags     := $(utest-ldflags)
galv-utest-pkgconf     := libelog libutils libstroll libcute

# ex: filetype=make :
