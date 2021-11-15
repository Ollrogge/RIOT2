# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

APPLICATION = ipsn22-baseline

ifeq (1, $(CRYPTOCELL_CIPHER))
	CFLAGS += -DCRYPTOCELL_CIPHER
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.cryptocell
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.random
endif

ifeq (1, $(CC_ECDSA))
	CFLAGS += -DCC_ECDSA
	CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(12*THREAD_STACKSIZE_DEFAULT\)
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.cryptocell
endif

ifeq (1, $(RIOT_CIPHER))
	CFLAGS += -DRIOT_CIPHER
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.riot
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.random
endif

ifeq (1, $(CRYPTOCELL_HASHES))
	CFLAGS += -DCRYPTOCELL_HASHES
	CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.cryptocell
endif

ifeq (1, $(RIOT_HASHES))
	CFLAGS += -DRIOT_HASHES
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.riot.hashes
endif

ifeq (1, $(SE_ECDSA))
	CFLAGS += -DSE_ECDSA
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.riot.hashes
endif

ifeq (1, $(MICRO_ECC_ECDSA))
	CFLAGS += -DMICRO_ECC_ECDSA
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.uecc
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.random
endif

ifeq (1, $(USE_ALL))
	CFLAGS += -DCRYPTOCELL_CIPHER
	CFLAGS += -DRIOT_CIPHER
	CFLAGS += -DCRYPTOCELL_HASHES
	CFLAGS += -DRIOT_HASHES
	CFLAGS += -DSE_ECDSA
	CFLAGS += -DCC_ECDSA
	CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.random
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.cryptocell
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.riot
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se
endif

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include