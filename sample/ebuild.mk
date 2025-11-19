################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

smpl-ldflags := \
	$(common-ldflags) \
	-Wl,-whole-archive $(BUILDDIR)/builtin_smpl.a -Wl,-no-whole-archive \
	-Wl,-z,start-stop-visibility=hidden \
	-lgalv

builtins               := builtin_smpl.a
builtin_smpl.a-objs    := common.o
builtin_smpl.a-cflags  := $(common-cflags)

bins                   := $(call kconf_enabled,GALV_SMPL_SESS,galv-smpl-sess)
galv-smpl-sess-objs    := $(call kconf_enabled,GALV_SMPL_SESS,sess_srv.o)
galv-smpl-sess-cflags  := $(common-cflags)
galv-smpl-sess-ldflags := $(smpl-ldflags)
galv-smpl-sess-pkgconf := libelog libutils

bins                       := $(call kconf_enabled,GALV_SMPL_DISC_SRV, \
                                                   galv-smpl-disc-srv)
galv-smpl-disc-srv-objs    := $(call kconf_enabled,GALV_SMPL_DISC_SRV, \
                                                   disc_srv.o)
galv-smpl-disc-srv-cflags  := $(common-cflags)
galv-smpl-disc-srv-ldflags := $(smpl-ldflags)
galv-smpl-disc-srv-pkgconf := libelog libutils

bins                       := $(call kconf_enabled,GALV_SMPL_ECHO_SRV, \
                                                   galv-smpl-echo-srv)
galv-smpl-echo-srv-objs    := $(call kconf_enabled,GALV_SMPL_ECHO_SRV, \
                                                   echo_srv.o)
galv-smpl-echo-srv-cflags  := $(common-cflags)
galv-smpl-echo-srv-ldflags := $(smpl-ldflags)
galv-smpl-echo-srv-pkgconf := libelog libutils

build: $(BUILDDIR)/galv-smpl-echo-clnt
$(BUILDDIR)/galv-smpl-echo-clnt: $(SRCDIR)/echo_clnt.sh | $(BUILDDIR)/
	@echo "  GENSH   $(@)"
	sed -e 's;@@BINDIR@@;$(BINDIR);g' \
	    $(<) > $(@)

clean: _clean
.PHONY: _clean
_clean:
	$(call rm_recipe,$(BUILDDIR)/galv-smpl-echo-clnt)

install: $(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt

.PHONY: $(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt
$(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt: $(BUILDDIR)/galv-smpl-echo-clnt
	$(call install_recipe,--mode=755,$(<),$(@))
	
uninstall: _uninstall
.PHONY: _uninstall
_uninstall:
	$(call rm_recipe,$(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt)

# ex: filetype=make :
