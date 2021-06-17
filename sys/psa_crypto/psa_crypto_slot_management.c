#include "psa/crypto_slot_management.h"

typedef struct
{
    psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];
    uint8_t key_slots_initialized : 1;
} psa_global_data_t;

static psa_global_data_t global_data;
