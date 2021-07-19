include ../Makefile.tests_common

# Test fails to build for these boards fails due to
# redefinition of define AES_COUNT in library, which
# is also defined in board header files
BOARD_BLACKLIST := stk3200 stk3600 stk3700

# due to memory constrains we ignore the cert test
CFLAGS += -DDO_NOT_TEST_CERT -DDO_NOT_TEST_SW_CRYPTO
USEPKG += cryptoauthlib
USEMODULE += cryptoauthlib_test
USEMODULE += embunit

include $(RIOTBASE)/Makefile.include
