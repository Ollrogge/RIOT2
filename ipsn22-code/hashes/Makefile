# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

APPLICATION = hashes
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)

ifeq (1, $(SOFTWARE))
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.software
endif

ifeq (1, $(USE_MULTIPLE_BACKENDS))
	CFLAGS += -DMULTIPLE_BACKENDS
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.multiple
endif

ifeq (1, $(TEST_STACK))
	CFLAGS += -DTEST_STACK
	CFLAGS += -DDEVELHELP=1
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.stack
endif

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include