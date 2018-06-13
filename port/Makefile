PKG_NAME=satufs
PKG_URL=
PKG_VERSION=
PKG_LICENSE=
PKG_SOURCE_LOCAL=$(RIOTBASE)/../satu

.PHONY: all

all: git-download prepare
	"$(MAKE)" -C $(PKG_BUILDDIR) -f $(CURDIR)/Makefile.satufs

include $(RIOTBASE)/pkg/pkg.mk
