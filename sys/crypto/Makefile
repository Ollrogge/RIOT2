ifeq (, $(RIOT_CHACHA_PRNG_DEFAULT))
    RIOT_CHACHA_PRNG_DEFAULT := $(shell head -c 64 /dev/urandom | hexdump -e '"0x%4xull,"')
endif

CFLAGS += -DRIOT_CHACHA_PRNG_DEFAULT="$(RIOT_CHACHA_PRNG_DEFAULT)"

ifneq (,$(filter psa_software_cipher,$(USEMODULE)))
  DIRS += psa_software
endif

include $(RIOTBASE)/Makefile.base
