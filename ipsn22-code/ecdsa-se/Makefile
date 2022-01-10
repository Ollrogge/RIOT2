# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

APPLICATION = ecdsa-se
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)

ifeq (1, $(USE_MULTIPLE_BACKENDS))
	CFLAGS += -DMULTIPLE_BACKENDS
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.multiple
endif

ifeq (1, $(TEST_TIME))
	CFLAGS += -DTEST_TIME
endif

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include