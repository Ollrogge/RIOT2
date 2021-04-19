include ../Makefile.tests_common

export TEST_KCONFIG ?= 1

CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(12*THREAD_STACKSIZE_DEFAULT\)

ARCHIVES += $(BINDIR)/pkg-build/psa_arch_tests/dev_apis/crypto/test_combine.a
ARCHIVES += $(BINDIR)/pkg-build/psa_arch_tests/val/val_nspe.a
ARCHIVES += $(BINDIR)/pkg-build/psa_arch_tests/platform/pal_nspe.a

include $(RIOTBASE)/Makefile.include
