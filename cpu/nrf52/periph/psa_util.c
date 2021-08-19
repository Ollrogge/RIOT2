#include "psa_periph_util.h"

psa_status_t cc310_to_psa_error(CRYSError_t error)
{
    switch(error) {
        case CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR:
        case CRYS_HASH_IS_NOT_SUPPORTED:
            return PSA_ERROR_NOT_SUPPORTED;
        case CRYS_HASH_USER_CONTEXT_CORRUPTED_ERROR:
            return PSA_ERROR_CORRUPTION_DETECTED;
        case CRYS_HASH_DATA_IN_POINTER_INVALID_ERROR:
        case CRYS_HASH_DATA_SIZE_ILLEGAL:
            return PSA_ERROR_DATA_INVALID;
        case CRYS_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR:
        case CRYS_HASH_ILLEGAL_PARAMS_ERROR:
        case CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR:
        case CRYS_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR:
        case CRYS_HASH_CTX_SIZES_ERROR:
            return PSA_ERROR_INVALID_ARGUMENT;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}
