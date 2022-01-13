## How To Use This Branch

### Using this Application
The default build of this application uses only one secure element.
To use two of them, build with `USE_MULTIPLE_BACKENDS=1`. Read below to learn how to connect two secure elements.

### NRF52 I2C
To use two secure elements via I2C you need to reconfigure two GPIOs.
In `boards/common/nrf52/include/cfg_i2c_default.h` I configured GPIOs 28 and 29 to be SCL and SDA lines. You can change those if you'd rather use others. You can then connect both SEs to the Nordic Board.

### Cryptoauthlib
To be able to use the Cryptoauth Library with multiple secure elements, we need a newer version of the package. This branch uses my [fork](https://github.com/Einhornhool/cryptoauthlib/commits/dev/riot-pkg-update).

#### Devices
Devices are defined in `pkg/cryptoauthlib/include/atca_params.h` as `ATCA_PARAM_I2C_DEVX`. Those values are used to define the location values (`PSA_ATCA_LOCATION_DEVX`) which are used by this application to access the correct device. This means that this application currently includes atca_params.h. This is not a final concept and may change in the future.

#### SE Driver Interface
Cryptoauthlib functions are accessed via the se interface in `pkg/cryptoauthlib/psa_se_driver/psa_atca_se_driver.c`. So far only some functions are implemented.

> Attention:
> The `atca_allocate` function is supposed to find a suitable key slot on a secure element. I have not yet implemented a way to do that and have hardcoded the key slot numbers that are returned and used (key slot 1 for ECC private keys, key slot 9 for ECC public keys), which are consistend with the configuration used [here](https://github.com/inetrg/EWSN-2021/tree/master/section-6/atecc608a_configure_and_lock). If you want to use other slots or multiple slots on the same device, you'll need to change it in the allocate function implemented in `psa_atca_se_driver.c`.

### PSA Crypto
This application contains two example functions that generate an elliptic curve key pair and perform an ECDSA operation.

#### Version 1
The `ecdsa_prim_se` function first generates a key pair with one of the SEs. When generating an ECC key, only the private key is stored on the Secure Element and the public key is returned by the ATCA driver.
PSA Crypto is implemented in a way that it stores the reference to the private key as well as the plain public key locally using the same key identifier.
This means, you can access both the private and the public key using the identifier returned by the `psa_generate_key` function.
Unfortunately this also means that both keys are stored with the location value assigned to the secure element, even though the public key is not stored on the SE (this is inconsistent and not great, but I haven't found a better solution, yet).

If you want to store both the private and public key on the secure element, you will need to export the public key and then import it again. This way it gets it's own key slot and identifier and can be used separate from the private key (see Version 2).

#### Version 2
The `ecdsa_sec_se` function exports the public key of the key pair generated in the first version and the imports it to the second secure element.
It then performs a hash signature operation using the private key stored on the first secure element and verifies the signature using the public key stored on the second secure element.