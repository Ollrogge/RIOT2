# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

APPLICATION = ecdsa-periph-se
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(12*THREAD_STACKSIZE_DEFAULT\)

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include