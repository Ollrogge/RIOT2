#include <stdio.h>
#include <stdint.h>

#ifdef CRYPTOCELL_CIPHER
#include "vendor/nrf52840.h"
#include "cryptocell_incl/ssi_aes.h"
#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_util.h"
#endif

#ifdef CRYPTOCELL_HASHES
#include "vendor/nrf52840.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_util.h"
#endif

#ifdef RIOT_CIPHER
#include "crypto/modes/cbc.h"
#endif

#ifdef SE_ECDSA
#include "cryptoauthlib.h"
#include "atca_params.h"
#endif

#ifdef CC_ECDSA
#include "vendor/nrf52840.h"
#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/crys_ecpki_build.h"
#include "cryptocell_incl/crys_ecpki_ecdsa.h"
#include "cryptocell_incl/crys_ecpki_kg.h"
#include "cryptocell_incl/crys_ecpki_domain.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_util.h"
#endif

#ifdef MICRO_ECC_ECDSA
#include "uECC.h"
#endif

#include "random.h"
#include "hashes/sha256.h"

#include "periph/gpio.h"

#define AES_128_KEY_SIZE    (16)
#define AES_256_KEY_SIZE    (32)
#define AES_CBC_IV_SIZE     (16)
#define ECDSA_MESSAGE_SIZE  (127)
#define UECC_CURVE_192_SIZE (24)
#define PUB_KEY_SIZE        (UECC_CURVE_192_SIZE * 2)
#define SHA256_DIGEST_SIZE  (32)

gpio_t active_gpio = GPIO_PIN(1, 8);

#if defined(CRYPTOCELL_CIPHER)
static uint8_t KEY_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
#endif

#if defined(RIOT_CIPHER)
static uint8_t KEY_256[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
#endif

#if defined(CRYPTOCELL_CIPHER) || defined(RIOT_CIPHER)
static uint8_t PLAINTEXT[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static uint8_t PLAINTEXT_LEN = 32;
static uint8_t CBC_CIPHER_LEN = 32;
#endif /* CIPHER */

#if defined(RIOT_HASHES)
uint8_t SHA256_MSG[] = {  0x09, 0xfc, 0x1a, 0xcc, 0xc2, 0x30, 0xa2, 0x05,
                                0xe4, 0xa2, 0x08, 0xe6, 0x4a, 0x8f, 0x20, 0x42,
                                0x91, 0xf5, 0x81, 0xa1, 0x27, 0x56, 0x39, 0x2d,
                                0xa4, 0xb8, 0xc0, 0xcf, 0x5e, 0xf0, 0x2b, 0x95};
size_t SHA256_MSG_LEN = 32;

uint8_t SHA256_DIG[] = {  0x4f, 0x44, 0xc1, 0xc7, 0xfb, 0xeb, 0xb6, 0xf9,
                                0x60, 0x18, 0x29, 0xf3, 0x89, 0x7b, 0xfd, 0x65,
                                0x0c, 0x56, 0xfa, 0x07, 0x84, 0x4b, 0xe7, 0x64,
                                0x89, 0x07, 0x63, 0x56, 0xac, 0x18, 0x86, 0xa4};
size_t SHA256_DIG_LEN = 32;
#endif

#if defined(CRYPTOCELL_HASHES)
uint8_t SHA512_MSG[] = {  0x8c, 0xcb, 0x08, 0xd2, 0xa1, 0xa2, 0x82, 0xaa,
                                0x8c, 0xc9, 0x99, 0x02, 0xec, 0xaf, 0x0f, 0x67,
                                0xa9, 0xf2, 0x1c, 0xff, 0xe2, 0x80, 0x05, 0xcb,
                                0x27, 0xfc, 0xf1, 0x29, 0xe9, 0x63, 0xf9, 0x9d};
size_t SHA512_MSG_LEN = 32;

uint8_t SHA512_DIG[] = {  0x45, 0x51, 0xde, 0xf2, 0xf9, 0x12, 0x73, 0x86,
                                0xee, 0xa8, 0xd4, 0xda, 0xe1, 0xea, 0x8d, 0x8e,
                                0x49, 0xb2, 0xad, 0xd0, 0x50, 0x9f, 0x27, 0xcc,
                                0xbc, 0xe7, 0xd9, 0xe9, 0x50, 0xac, 0x7d, 0xb0,
                                0x1d, 0x5b, 0xca, 0x57, 0x9c, 0x27, 0x1b, 0x9f,
                                0x2d, 0x80, 0x67, 0x30, 0xd8, 0x8f, 0x58, 0x25,
                                0x2f, 0xd0, 0xc2, 0x58, 0x78, 0x51, 0xc3, 0xac,
                                0x8a, 0x0e, 0x72, 0xb4, 0xe1, 0xdc, 0x0d, 0xa6};
size_t SHA512_DIG_LEN = 64;
#endif

#ifdef CC_ECDSA
extern CRYS_RND_State_t*     rndState_ptr;

CRYS_ECPKI_Domain_t* pDomain;
SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc;
#endif

static void _test_init(void)
{
    gpio_init(active_gpio, GPIO_OUT);
    gpio_set(active_gpio);
}

#ifdef CRYPTOCELL_CIPHER
void cryptocell_aes_cbc_128(void)
{
    SaSiAesUserKeyData_t key;
    SaSiAesUserContext_t ctx;
    uint8_t iv[AES_CBC_IV_SIZE];
    uint8_t result[CBC_CIPHER_LEN];
    size_t output_length;
    int ret;

    key.pKey = KEY_128;
    key.keySize = AES_128_KEY_SIZE;

    puts("AES 128 IV Generation");
    gpio_clear(active_gpio);
    random_bytes(iv, AES_CBC_IV_SIZE);
    gpio_set(active_gpio);

    puts("AES 128 Init, Set Key, Set IV");
    gpio_clear(active_gpio);
    ret = SaSi_AesInit(&ctx, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC, SASI_AES_PADDING_NONE);
    if (ret != SASI_OK) {
        printf("SaSi Init failed: %x\n", ret);
        return;
    }

    ret = SaSi_AesSetKey(&ctx, SASI_AES_USER_KEY, &key, sizeof(key));
    if (ret != SASI_OK) {
        printf("SaSi AES Set Key failed: %x\n", ret);
        return;
    }

    ret = SaSi_AesSetIv(&ctx, iv);
    if (ret != SASI_OK) {
        printf("SaSi Init failed: %x\n", ret);
        return;
    }
    gpio_set(active_gpio);

    puts("AES 128 Encryption");
    gpio_clear(active_gpio);
    cryptocell_enable();
    ret = SaSi_AesBlock(&ctx, PLAINTEXT, PLAINTEXT_LEN, result);
    cryptocell_disable();
    if (ret != SASI_OK) {
        printf("SaSi AES Block failed: %x\n", ret);
        return;
    }

    cryptocell_enable();
    ret = SaSi_AesFinish(&ctx, 0, PLAINTEXT, PLAINTEXT_LEN, result, &output_length);
    cryptocell_disable();
    gpio_set(active_gpio);
    if (ret != SASI_OK) {
        printf("SaSi AES Finish failed: %x\n", ret);
        return;
    }
    puts("CryptoCell AES Done");
}
#endif /* CRYPTOCELL_CIPHER */

#if defined(CRYPTOCELL_HASHES)
void cryptocell_sha512(void)
{
    CRYS_HASHUserContext_t ctx;
    CRYS_HASH_Result_t result;
    int ret;

    puts("SHA512 Init");
    gpio_clear(active_gpio);
    ret = CRYS_HASH_Init(&ctx, CRYS_HASH_SHA512_mode);
    gpio_set(active_gpio);
    if (ret != CRYS_OK) {
        printf("CRYS Init failed: %x\n", ret);
        return;
    }

    puts("SHA512 Update");
    cryptocell_enable();
    gpio_clear(active_gpio);
    ret = CRYS_HASH_Update(&ctx, SHA512_MSG, SHA512_MSG_LEN);
    gpio_set(active_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        printf("SHA512 Update failed: %x\n", ret);
        return;
    }

    puts("SHA512 Finish");
    cryptocell_enable();
    gpio_clear(active_gpio);
    ret = CRYS_HASH_Finish(&ctx, result);
    gpio_set(active_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        printf("SHA512 Finish failed: %x\n", ret);
        return;
    }
    puts("CryptoCell SHA512 Done");
}
#endif

#if defined(RIOT_HASHES)
void riot_sha256(void)
{
    sha256_context_t ctx;
    uint8_t result[SHA256_DIG_LEN];

    puts("SHA256 Init");
    gpio_clear(active_gpio);
    sha256_init(&ctx);
    gpio_set(active_gpio);

    puts("SHA256 Update");
    gpio_clear(active_gpio);
    sha256_update(&ctx, SHA256_MSG, SHA256_MSG_LEN);
    gpio_set(active_gpio);

    puts("SHA256 Finish");
    gpio_clear(active_gpio);
    sha256_final(&ctx, result);
    gpio_set(active_gpio);

    puts("RIOT SHA256 Done");
}
#endif

#ifdef RIOT_CIPHER
void riot_aes_cbc_256(void)
{
    int ret;

    cipher_t ctx;
    uint8_t iv[AES_CBC_IV_SIZE];
    uint8_t result[CBC_CIPHER_LEN];

    puts("AES 256 IV Generation");
    gpio_clear(active_gpio);
    random_bytes(iv, AES_CBC_IV_SIZE);
    gpio_set(active_gpio);

    puts("AES 256 Init");
    gpio_clear(active_gpio);
    ret = cipher_init(&ctx, CIPHER_AES, KEY_256, AES_256_KEY_SIZE);
    gpio_set(active_gpio);
    if (ret != CIPHER_INIT_SUCCESS) {
        printf("AES 256 Init failed: %d\n", ret);
        return;
    }

    puts("AES 256 Encryption");
    gpio_clear(active_gpio);
    ret = cipher_encrypt_cbc(&ctx, iv, PLAINTEXT, PLAINTEXT_LEN, result);
    gpio_set(active_gpio);
    if (ret <= 0) {
        printf("AES 256 Encrypt failed: %d\n", ret);
        return;
    }
    puts("RIOT AES Done");
}
#endif /* RIOT_CIPHER */

#ifdef CC_ECDSA
void cc_ecdsa(void)
{
    int ret;
    CRYS_ECPKI_UserPrivKey_t priv_key;
    CRYS_ECPKI_UserPublKey_t pub_key;

    CRYS_ECPKI_KG_FipsContext_t FipsBuff;
    CRYS_ECPKI_KG_TempData_t TempECCKGBuff;

    CRYS_ECDSA_SignUserContext_t SignUserContext;
    CRYS_ECDSA_VerifyUserContext_t VerifyUserContext;
    CRYS_ECDH_TempData_t signOutBuff;
    CRYS_ECPKI_HASH_OpMode_t ecdsa_hash_mode = CRYS_ECPKI_AFTER_HASH_SHA256_mode;
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint32_t ecdsa_sig_size = 64;
    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp192r1);

    cryptocell_enable();
    gpio_clear(active_gpio);
    ret = CRYS_ECPKI_GenKeyPair(rndState_ptr, rndGenerateVectFunc, pDomain, &priv_key, &pub_key, &TempECCKGBuff, &FipsBuff);
    gpio_set(active_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK){
        printf("CryptoCell ECDSA GenKey failed with 0x%x \n",ret);
        return;
    }

    cryptocell_enable();
    gpio_clear(active_gpio);
    ret = CRYS_HASH(CRYS_HASH_SHA256_mode, msg, ECDSA_MESSAGE_SIZE, (uint32_t *) hash);
    gpio_set(active_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        printf("CRYS Hash failed: %x\n", ret);
        return;
    }

    cryptocell_enable();
    gpio_clear(active_gpio);
    ret = CRYS_ECDSA_Sign(rndState_ptr, rndGenerateVectFunc,
    &SignUserContext, &priv_key, ecdsa_hash_mode, hash, SHA256_DIGEST_SIZE, (uint8_t *) &signOutBuff, &ecdsa_sig_size);
    gpio_set(active_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK){
        printf("CryptoCell ECDSA Sign failed with 0x%x \n",ret);
        return;
    }

    cryptocell_enable();
    gpio_clear(active_gpio);
    ret = CRYS_ECDSA_Verify (&VerifyUserContext, &pub_key, ecdsa_hash_mode, (uint8_t *) &signOutBuff, ecdsa_sig_size, hash, SHA256_DIGEST_SIZE);
    gpio_set(active_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK){
        printf("CryptoCell ECDSA Verify failed with 0x%x \n",ret);
        return;
    }
    puts("CryptoCell ECDSA Done");
}
#endif

#ifdef SE_ECDSA
void se1_ecdsa(void)
{
    uint8_t UserPubKey[ATCA_PUB_KEY_SIZE];
    uint8_t key_id = 1;

    uint8_t signature[ATCA_SIG_SIZE];
    bool is_verified = false;

    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[ATCA_SHA_DIGEST_SIZE];

    ATCA_STATUS status;
    ATCADevice dev = NULL;
    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *) &atca_params[0].cfg;

    puts("SE Device Init");
    gpio_clear(active_gpio);
    status = atcab_init_ext(&dev, cfg);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS) {
        printf("SE1 Device Init failed with 0x%x \n",status);
        return;
    }

    puts("SE Key Generation");
    gpio_clear(active_gpio);
    status = calib_genkey(dev, key_id, UserPubKey);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS){
        printf("SE1 Key Generation failed with 0x%x \n",status);
        return;
    }

    puts("SE Message Hashing");
    gpio_clear(active_gpio);
    sha256(msg, ECDSA_MESSAGE_SIZE, hash);
    gpio_set(active_gpio);

    puts("SE1 Sign");
    gpio_clear(active_gpio);
    status = calib_sign(dev, key_id, hash, signature);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS){
        printf("SE1 Signing failed with 0x%x \n",status);
        return;
    }

    puts("SE1 Verify");
    gpio_clear(active_gpio);
    status = calib_verify_extern(dev, hash, signature, UserPubKey, &is_verified);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS){
        printf("SE1 Verification failed with 0x%x \n",status);
        return;
    }
    puts("SE1 ECDSA Done");
}

void se2_ecdsa(void)
{
    uint8_t UserPubKey[ATCA_PUB_KEY_SIZE];
    uint8_t key_id = 1;

    uint8_t signature[ATCA_SIG_SIZE];
    bool is_verified = false;

    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[ATCA_SHA_DIGEST_SIZE];

    ATCA_STATUS status;
    ATCADevice dev = NULL;
    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *) &atca_params[1].cfg;

    puts("SE Device Init");
    gpio_clear(active_gpio);
    status = atcab_init_ext(&dev, cfg);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS) {
        printf("SE2 Device Init failed with 0x%x \n",status);
        return;
    }

    puts("SE Key Generation");
    gpio_clear(active_gpio);
    status = calib_genkey(dev, key_id, UserPubKey);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS){
        printf("SE2 Key Generation failed with 0x%x \n",status);
        return;
    }

    puts("SHA256 Message Hashing");
    gpio_clear(active_gpio);
    sha256(msg, ECDSA_MESSAGE_SIZE, hash);
    gpio_set(active_gpio);

    puts("SE2 Sign");
    gpio_clear(active_gpio);
    status = calib_sign(dev, key_id, hash, signature);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS){
        printf("SE2 Signing failed with 0x%x \n",status);
        return;
    }

    puts("SE2 Verify");
    gpio_clear(active_gpio);
    status = calib_verify_extern(dev, hash, signature, UserPubKey, &is_verified);
    gpio_set(active_gpio);
    if (status != ATCA_SUCCESS){
        printf("SE2 Verification failed with 0x%x \n",status);
        return;
    }
    puts("SE2 ECDSA Done");
}
#endif /* SE_ECDSA */

#ifdef MICRO_ECC_ECDSA
void micro_ecc_ecdsa(void)
{
    struct uECC_Curve_t *curve;
    uint8_t userPrivKey1[UECC_CURVE_192_SIZE];
    uint8_t userPubKey1[PUB_KEY_SIZE];
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t signature[PUB_KEY_SIZE];

    int ret;

    puts("uECC Init Curve");
    gpio_clear(active_gpio);
    curve = (struct uECC_Curve_t*)uECC_secp192r1();
    gpio_set(active_gpio);

    puts("uECC Key Generation");
    gpio_clear(active_gpio);
    ret = uECC_make_key(userPubKey1, userPrivKey1, curve);
    gpio_set(active_gpio);
    if(!ret) {
        puts("uECC Key Generation failed");
        return;
    }

    puts("SHA256 Message Hashing");
    gpio_clear(active_gpio);
    sha256(msg, ECDSA_MESSAGE_SIZE, hash);
    gpio_set(active_gpio);

    puts("uECC Sign");
    gpio_clear(active_gpio);
    ret = uECC_sign(userPrivKey1, hash, SHA256_DIGEST_SIZE, signature, curve);
    gpio_set(active_gpio);
    if(!ret) {
        puts("uECC Signing failed");
        return;
    }

    puts("uECC Verify");
    gpio_clear(active_gpio);
    ret = uECC_verify(userPubKey1, hash, SHA256_DIGEST_SIZE, signature, curve);
    gpio_set(active_gpio);
    if(!ret) {
        puts("INVALID");
    }
    puts("uECC ECDSA Done");
}
#endif /* UECC_ECDSA */

int main(void)
{
    _test_init();
#ifdef CRYPTOCELL_CIPHER
    cryptocell_aes_cbc_128();
#endif
#ifdef RIOT_CIPHER
    riot_aes_cbc_256();
#endif
#ifdef CRYPTOCELL_HASHES
    cryptocell_sha512();
#endif
#ifdef RIOT_HASHES
    riot_sha256();
#endif
#ifdef CC_ECDSA
    cc_ecdsa();
#endif
#ifdef SE_ECDSA
    se1_ecdsa();
    se2_ecdsa();
#endif
#ifdef MICRO_ECC_ECDSA
    micro_ecc_ecdsa();
#endif
    return 0;
}