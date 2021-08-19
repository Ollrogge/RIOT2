BASE_MODULE := hashes

# enable submodules
SUBMODULES := 1

ifneq (,$(filter psa_riot_hashes_%,$(USEMODULE)))
  DIRS += psa_riot_hashes
endif

include $(RIOTBASE)/Makefile.base
