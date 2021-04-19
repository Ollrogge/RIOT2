PKG_NAME=psa_arch_tests
PKG_URL=https://github.com/ARM-software/psa-arch-tests
PKG_VERSION=d4b75cc0a8e3df96c2240d7f28d2aac4b0def0f8
PKG_LICENSE=Apache-2.0

include $(RIOTBASE)/pkg/pkg.mk

INCLUDE_PATHS=$(RIOTBASE)/cpu/$(CPU)/include;$(RIOTBASE)/sys/include;$(RIOTBASE)/core/include;$(RIOTBASE)/sys/psa_crypto

ifneq (,$(filter cryptoauthlib_contrib,$(USEMODULE)))
  INCLUDE_PATHS+=;$(RIOTPKG)/cryptoauthlib/hashes/include;$(RIOTBASE)/build/pkg/cryptoauthlib/lib
endif

# $(info $$Usemodule is [${USEMODULE}])
.PHONY: all..cmake_version_supported

CMAKE_MINIMAL_VERSION = 3.10

TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/xcompile-toolchain.cmake

all: psa_arch_tests

psa_arch_tests: $(PKG_BUILD_DIR)/Makefile
	env -u CC -u CFLAGS \
 	$(MAKE) -C $(PKG_BUILD_DIR)

# Note: Only supports architectures armv8m_ml, armv8m_bl and armv7m
$(PKG_BUILD_DIR)/Makefile: $(TOOLCHAIN_FILE)
	cp -r tgt_dev_apis_riot $(PKG_SOURCE_DIR)/api-tests/platform/targets && \
	cp $(BINDIR)/riotbuild/riotbuild.h $(PKG_SOURCE_DIR)/api-tests/platform/targets/tgt_dev_apis_riot/nspe && \
	cp $(BINDIR)/generated/autoconf.h $(PKG_SOURCE_DIR)/api-tests/platform/targets/tgt_dev_apis_riot/nspe && \
	cp $(RIOTBASE)/tests/psa_crypto/testsuite.db $(PKG_SOURCE_DIR)/api-tests/dev_apis/crypto && \
	env -u CC -u CFLAGS cmake \
		  -G"Unix Makefiles" \
		  -H$(PKG_SOURCE_DIR)/api-tests \
		  -B$(PKG_BUILD_DIR) \
		  -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
		  -Wno-dev \
		  -DTARGET=tgt_dev_apis_riot \
		  -DCPU_ARCH=$(CPU_ARCH) \
		  -DSUITE=CRYPTO \
		  -DPSA_INCLUDE_PATHS="$(INCLUDE_PATHS)" \
		  -DWATCHDOG_AVAILABLE=0

$(TOOLCHAIN_FILE): git-download
	$(RIOTTOOLS)/cmake/generate-xcompile-toolchain.sh > $(TOOLCHAIN_FILE)

git-download: | ..cmake_version_supported

..cmake_version_supported:
	@ # Remove '-rcX' from version as they are not well handled
	$(Q)\
	CMAKE_VERSION=$$(cmake --version | sed -n '1 {s/cmake version //;s/-rc.*//;p;}'); \
	$(RIOTTOOLS)/has_minimal_version/has_minimal_version.sh "$${CMAKE_VERSION}" "$(CMAKE_MINIMAL_VERSION)" cmake

clean::
	@rm -rf $(BINDIR)/$(PKG_NAME).a
	@rm -rf $(BINDIR)/$(PKG_TEST_NAME).a
