################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

config-in       := Config.in
config-h        := galv/priv/config.h
config-obj      := config.o

HEADERDIR       := $(CURDIR)/include
headers          = galv/cdefs.h
headers         += galv/acceptor.h
headers         += galv/conn.h
headers         += $(call kconf_enabled,GALV_GATE,galv/gate.h)
headers         += $(call kconf_enabled,GALV_FABRIC,galv/fabric.h)
headers         += $(call kconf_enabled,GALV_REPO,galv/repo.h)
headers         += $(call kconf_enabled,GALV_UNIX,galv/unix.h)
headers         += $(call kconf_enabled,GALV_BUFF,galv/buffer.h)
headers         += $(call kconf_enabled,GALV_FRAG,galv/priv/fragment.h)

subdirs         := lib

ifeq ($(CONFIG_GALV_UTEST),y)
subdirs         += test
test-deps       := lib
endif # ($(CONFIG_GALV_UTEST),y)

define libgalv_pkgconf_tmpl
prefix=$(PREFIX)
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: libgalv
Description: Galv library
Version: $(VERSION)
Requires: libutils libstroll
Requires.private: libutils libstroll $(call kconf_enabled,GALV_LOG,libelog)
Cflags: -I$${includedir}
Libs: -L$${libdir} -Wl,--push-state,--as-needed -lgalv -Wl,--pop-state
endef

pkgconfigs      := libgalv.pc
libgalv.pc-tmpl := libgalv_pkgconf_tmpl

################################################################################
# Source code tags generation
################################################################################

tagfiles := $(shell find $(addprefix $(CURDIR)/,$(subdirs)) \
                         $(HEADERDIR) \
                         -type f)

#################################################################################
## Documentation generation
#################################################################################
#
#doxyconf  := $(CURDIR)/sphinx/Doxyfile
#doxyenv   := SRCDIR="$(HEADERDIR) $(SRCDIR)"
#
#sphinxsrc := $(CURDIR)/sphinx
#sphinxenv := \
#	VERSION="$(VERSION)" \
#	$(if $(strip $(EBUILDDOC_TARGET_PATH)), \
#	     EBUILDDOC_TARGET_PATH="$(strip $(EBUILDDOC_TARGET_PATH))") \
#	$(if $(strip $(EBUILDDOC_INVENTORY_PATH)), \
#	     EBUILDDOC_INVENTORY_PATH="$(strip $(EBUILDDOC_INVENTORY_PATH))") \
#	$(if $(strip $(STROLLDOC_TARGET_PATH)), \
#	     STROLLDOC_TARGET_PATH="$(strip $(STROLLDOC_TARGET_PATH))") \
#	$(if $(strip $(STROLLDOC_INVENTORY_PATH)), \
#	     STROLLDOC_INVENTORY_PATH="$(strip $(STROLLDOC_INVENTORY_PATH))") \
#	$(if $(strip $(UTILSDOC_TARGET_PATH)), \
#	     UTILSDOC_TARGET_PATH="$(strip $(UTILSDOC_TARGET_PATH))") \
#	$(if $(strip $(UTILSDOC_INVENTORY_PATH)), \
#	     UTILSDOC_INVENTORY_PATH="$(strip $(UTILSDOC_INVENTORY_PATH))") \
#	$(if $(strip $(CUTEDOC_TARGET_PATH)), \
#	     CUTEDOC_TARGET_PATH="$(strip $(CUTEDOC_TARGET_PATH))") \
#	$(if $(strip $(CUTEDOC_INVENTORY_PATH)), \
#	     CUTEDOC_INVENTORY_PATH="$(strip $(CUTEDOC_INVENTORY_PATH))")
