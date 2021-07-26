BASE_MODULE := hashes

# enable submodules
SUBMODULES := 1

ifneq (,$(filter psa_software_hashes,$(USEMODULE)))
  DIRS += psa_software
endif

include $(RIOTBASE)/Makefile.base
