/* Auto-generated config file atca_config.h */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

#define ATCA_PRINTF
#define ATCA_HAL_I2C
#define ATCA_USE_ATCAB_FUNCTIONS

/* Included device support */
#define ATCA_ATECC508A_SUPPORT
#define ATCA_ATECC608A_SUPPORT

/** Define if cryptoauthlib is to use the maximum execution time method */
/* #undef ATCA_NO_POLL */


/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif

/** Define platform malloc/free */
#define ATCA_PLATFORM_MALLOC    malloc
#define ATCA_PLATFORM_FREE      free

#define atca_delay_ms   hal_delay_ms
#define atca_delay_us   hal_delay_us

#endif // ATCA_CONFIG_H
