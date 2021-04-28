## Testsuite for PSA Crypto API

This test application builds and runs the PSA Architecture Testsuite (https://github.com/ARM-software/psa-arch-tests).

The cryptographic algorithms to build the PSA Crypto API with can be configured using the app.config file or menuconfig.
The corresponding test cases should be configured by adding them to the testsuite.db file.

### Tests for Hashes:
| Test Name | Test Function
| ----------| -------------------
| test_c006 | *psa_hash_compute*
| test_c007 | *psa_hash_compare*
| test_c011 | *psa_hash_setup*
| test_c012 | *psa_hash_update*
| test_c013 | *psa_hash_verify*
| test_c014 | *psa_hash_finish*
| test_c015 | *psa_hash_abort*

