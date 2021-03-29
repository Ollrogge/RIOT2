PKG_SOURCE_LOCAL=/home/lena/Dokumente/work/repos/psa-arch-tests
PKG_NAME=psa-arch-tests
PKG_URL=https://github.com/ARM-software/psa-arch-tests
PKG_VERSION=d15ee41bfd7e6e568e3b7bd0f42ea97c687d3389
PKG_LICENSE=Apache-2.0
PKG_TEST_NAME=psa_arch_tests

include $(RIOTBASE)/pkg/pkg.mk

CFLAGS += -specs=nosys.specs -mfloat-abi=hard -mfpu=fpv4-sp-d16

.PHONY: all..cmake_version_supported

CMAKE_MINIMAL_VERSION = 3.10

TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/xcompile-toolchain.cmake

ifeq (1, $(or $(CPU_CORE_CORTEX_M23), $(CPU_CORE_CORTEX_M33)))
	THIS_ARCH=armv8m_ml
	# or armv8m_bl ???
else 
	THIS_ARCH=armv7m
endif

all: psa_arch_tests

psa_arch_tests: $(PKG_BUILD_DIR)/Makefile
# 	$(MAKE) -C $(PKG_BUILD_DIR)
# 	cp $(PKG_BUILD_DIR)/libcryptoauth.a $(BINDIR)/$(PKG_NAME).a

$(PKG_BUILD_DIR)/Makefile: $(TOOLCHAIN_FILE)
	cd $(RIOTBASE)/build/pkg/psa-arch-tests/api-tests && \
	mkdir BUILD && cd BUILD && \
	cmake ../ \
		  -G"Unix Makefiles" \
		  -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
		  -Wno-dev \
		  -DTARGET=tgt_dev_apis_riot \
		  -DCPU_ARCH=$(THIS_ARCH) \
		  -DSUITE=CRYPTO \
		  -DPSA_INCLUDE_PATHS="$(RIOTBASE)/sys/include;$(RIOTBASE)/core/include" \
		  -DPSA_CRYPTO_LIB_FILENAME=$(RIOTBASE)/tests/psa_crypto/libpsacrypto.a \
		  -DWATCHDOG_AVAILABLE=0 \
	&& cmake --build .

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
