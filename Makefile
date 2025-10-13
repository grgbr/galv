################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

override PACKAGE := galv
override VERSION := 1.0
EXTRA_CFLAGS     := -O2 -DNDEBUG -Wall -Wextra -Wformat=2
EXTRA_LDFLAGS    := -O2

export VERSION EXTRA_CFLAGS EXTRA_LDFLAGS

ifeq ($(strip $(EBUILDDIR)),)
ifneq ($(realpath ebuild/main.mk),)
EBUILDDIR := $(realpath ebuild)
else  # ($(realpath ebuild/main.mk),)
EBUILDDIR := $(realpath /usr/share/ebuild)
endif # !($(realpath ebuild/main.mk),)
endif # ($(strip $(EBUILDDIR)),)

ifeq ($(realpath $(EBUILDDIR)/main.mk),)
$(error '$(EBUILDDIR)': no valid eBuild install found !)
endif # ($(realpath $(EBUILDDIR)/main.mk),)

include $(EBUILDDIR)/main.mk


#define pkgconf
#$(shell env PKG_CONFIG_LIBDIR=$(PKG_CONFIG_LIBDIR) \
#            PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) \
#            pkg-config $(1))
#endef
#
#CFLAGS  := -D_GNU_SOURCE -I. -I$(CURDIR)/include $(EXTRA_CFLAGS) $(call pkgconf,--cflags libutils libelog libstroll)
#LDFLAGS := $(EXTRA_LDFLAGS) $(call pkgconf,--libs libelog libutils libstroll)
#
#.PHONY: all
##all: $(BUILDDIR)/srv $(BUILDDIR)/test-clnt
#all: $(BUILDDIR)/lib/libgalv.a \
#     $(BUILDDIR)/test/galvut-ncclnt \
#     $(BUILDDIR)/test/galvut-ncsvc
#
#lib-objs := unix.o acceptor.o conn.o repo.o fabric.o common.o
#$(BUILDDIR)/lib/libgalv.a: $(addprefix $(BUILDDIR)/lib/,$(lib-objs))
#	$(AR) rcs $(@) $(^)
#
#$(BUILDDIR)/lib/%.o: $(CURDIR)/lib/%.c | $(BUILDDIR)/lib/
#	$(CC) $(CFLAGS) -o $(@) -c $(<)
#
#$(BUILDDIR)/test/galvut-ncsvc: $(CURDIR)/test/ncsvc.c \
#                               $(BUILDDIR)/lib/libgalv.a \
#                               | $(BUILDDIR)/test/
#	$(CC) $(CFLAGS) -o $(@) $(^) $(LDFLAGS)
#	
#$(BUILDDIR)/test/galvut-ncclnt: $(CURDIR)/test/ncclnt.c \
#                                | $(BUILDDIR)/test/
#	$(CC) $(CFLAGS) -o $(@) $(^) $(LDFLAGS)
#
#srv-srcs := srv.c lib/unix.c lib/conn.c lib/fabric.c
#$(BUILDDIR)/srv: $(addprefix $(CURDIR)/,$(srv-srcs)) | $(BUILDDIR)/
#	$(CC) $(CFLAGS) $(^) $(LDFLAGS) -o $(@)
#
#clnt-srcs := test_clnt.c
#$(BUILDDIR)/test-clnt: $(addprefix $(CURDIR)/,$(clnt-srcs)) | $(BUILDDIR)/
#	$(CC) $(CFLAGS) $(^) $(LDFLAGS) -o $(@)
#
#.PHONY: clean
#clean:
#	$(RM) $(BUILDDIR)/srv $(BUILDDIR)/test-clnt
#	$(RM) -r $(BUILDDIR)/lib
#
#$(BUILDDIR)/ $(BUILDDIR)/lib/ $(BUILDDIR)/test/:
#	@mkdir -p $(@)
#	
