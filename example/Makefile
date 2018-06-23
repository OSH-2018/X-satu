# name of your application
APPLICATION = demo

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# Modules to include:
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

# Use MTD (flash layer)
USEMODULE += mtd

# Use VFS
USEMODULE += vfs

# Use satufs
EXTERNAL_MODULE_DIRS += $(RIOTBASE)/../port
INCLUDES += -I$(RIOTBASE)/../satu
INCLUDES += -I$(RIOTBASE)/../port
DIRS += $(RIOTBASE)/../port/fs
DIRS += $(RIOTBASE)/../port
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_sock_udp
USEMODULE += satufs
USEMODULE += satufs_fs
CFLAGS += -DVFS_FILE_BUFFER_SIZE=52 -DVFS_DIR_BUFFER_SIZE=44

# Network Config
ifeq ($(BOARD), native)
	CFLAGS += -DHOST_IPV6=\"$(shell ip -f inet6 addr show tap0 | awk '/inet6 / {print $$2}' | cut -f1 -d/)\"
endif

include $(RIOTBASE)/Makefile.include
