################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

smpl-ldflags := \
	$(common-ldflags) \
	-L$(BUILDDIR)/../lib \
	-Wl,-whole-archive $(BUILDDIR)/builtin_smpl.a -Wl,-no-whole-archive \
	-Wl,-z,start-stop-visibility=hidden \
	-Wl,--push-state,--as-needed -lgalv_common -Wl,--pop-state

builtins                     := builtin_smpl.a
builtin_smpl.a-objs          := common.o
builtin_smpl.a-cflags        := $(common-cflags)

bins                         += $(call kconf_enabled,GALV_SMPL_DISC_SRV, \
                                                     galv-smpl-disc-srv)
galv-smpl-disc-srv-objs      := $(call kconf_enabled,GALV_SMPL_DISC_SRV, \
                                                     disc_srv.o)
galv-smpl-disc-srv-cflags    := $(common-cflags)
galv-smpl-disc-srv-ldflags   := $(smpl-ldflags) -lgalv_svc
galv-smpl-disc-srv-pkgconf   := libelog libutils

bins                         += $(call kconf_enabled,GALV_SMPL_DISC_CLNT, \
                                                     galv-smpl-disc-clnt)
galv-smpl-disc-clnt-objs     := $(call kconf_enabled,GALV_SMPL_DISC_CLNT, \
                                                     disc_clnt.o)
galv-smpl-disc-clnt-cflags   := $(common-cflags)
galv-smpl-disc-clnt-ldflags  := $(smpl-ldflags) -lgalv_async_clnt
galv-smpl-disc-clnt-pkgconf  := libelog libutils $(timer-pkgconf)

bins                         += $(call kconf_enabled,GALV_SMPL_ECHO_CLNT, \
                                                     galv-smpl-echo-clnt)
galv-smpl-echo-clnt-objs     := $(call kconf_enabled,GALV_SMPL_ECHO_CLNT, \
                                                     echo_clnt.o)
galv-smpl-echo-clnt-cflags   := $(common-cflags)
galv-smpl-echo-clnt-ldflags  := $(smpl-ldflags) -lgalv_async_clnt
galv-smpl-echo-clnt-pkgconf  := libelog libutils $(timer-pkgconf)

bins                         += $(call kconf_enabled,GALV_SMPL_ECHO_SRV, \
                                                     galv-smpl-echo-srv)
galv-smpl-echo-srv-objs      := $(call kconf_enabled,GALV_SMPL_ECHO_SRV, \
                                                     echo_srv.o)
galv-smpl-echo-srv-cflags    := $(common-cflags)
galv-smpl-echo-srv-ldflags   := $(smpl-ldflags) -lgalv_svc
galv-smpl-echo-srv-pkgconf   := libelog libutils

bins                         += $(call kconf_enabled,GALV_SMPL_SESS_SRV, \
                                                     galv-smpl-sess-srv)
galv-smpl-sess-srv-objs      := $(call kconf_enabled,GALV_SMPL_SESS_SRV, \
                                                     sess_srv.o)
galv-smpl-sess-srv-cflags    := $(common-cflags)
galv-smpl-sess-srv-ldflags   := $(smpl-ldflags) -lgalv_svc
galv-smpl-sess-srv-pkgconf   := libelog libutils

ifeq ($(CONFIG_GALV_SMPL_ECHO_CLNT),y)

build: $(BUILDDIR)/galv-smpl-echo-clnt.sh
$(BUILDDIR)/galv-smpl-echo-clnt.sh: $(SRCDIR)/echo_clnt.sh | $(BUILDDIR)/
	@echo "  GENSH   $(@)"
	sed -e 's;@@BINDIR@@;$(BINDIR);g' \
	    $(<) > $(@)

clean: _clean
.PHONY: _clean
_clean:
	$(call rm_recipe,$(BUILDDIR)/galv-smpl-echo-clnt.sh)

install: $(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt.sh

.PHONY: $(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt.sh
$(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt.sh: $(BUILDDIR)/galv-smpl-echo-clnt.sh
	$(call install_recipe,--mode=755,$(<),$(@))
	
uninstall: _uninstall
.PHONY: _uninstall
_uninstall:
	$(call rm_recipe,$(DESTDIR)$(BINDIR)/galv-smpl-echo-clnt.sh)

endif # ($(CONFIG_GALV_SMPL_ECHO_CLNT),y)

# ex: filetype=make :
