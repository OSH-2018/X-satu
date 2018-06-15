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
USEMODULE += satufs
USEMODULE += satufs_fs
CFLAGS += -DVFS_FILE_BUFFER_SIZE=52 -DVFS_DIR_BUFFER_SIZE=44

include $(RIOTBASE)/Makefile.include
