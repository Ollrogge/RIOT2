# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

APPLICATION = hmac_sha256_se

ifeq (1, $(TEST_TIME))
	CFLAGS += -DTEST_TIME
endif

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include