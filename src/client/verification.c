#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "sgx_quote_3.h"
#include "sgx_urts.h"
#include "sgx_pce.h"
#include "sgx_error.h"

#include "occlum_dcap.h"

unsigned char* base64_decode(const char* encoded_data, size_t* output_length) {
    BIO *bio, *b64;
    size_t input_length = strlen(encoded_data);

    *output_length = (input_length * 3) / 4;
    unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    bio = BIO_new_mem_buf(encoded_data, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *output_length = BIO_read(bio, decoded_data, input_length);
    BIO_free_all(bio);

    return decoded_data;
}

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;

    char *nonce = argv[2];

    size_t quote_size = 0;
    uint8_t *quote_buffer = base64_decode(argv[1], &quote_size);
    if (!quote_buffer) { printf("Invalid Base64\n"); return 1; }

    sgx_quote3_t *p_quote = (sgx_quote3_t *)quote_buffer;
    sgx_report_body_t *p_rep_body = (sgx_report_body_t *)(&p_quote->report_body);
    sgx_report_data_t *p_rep_data = (sgx_report_data_t *)(&p_rep_body->report_data);

    printf("nonce: %s\n", nonce);
    printf("Report Data in Quote : ", p_rep_data.d);

    size_t nonce_len = strlen(nonce);
    if (nonce_len > sizeof(p_rep_data.d)) {
        nonce_len = sizeof(p_rep_data.d); // Truncate if too long
    }

    if (memcmp(p_rep_data.d, nonce, nonce_len) != 0)
        printf("   [!] Error: Nonce mismatch in report data.\n");

    uint32_t supplemental_size = dcap_get_supplemental_data_size(handle);
    printf("supplemental_size size = %d\n", supplemental_size);
    uint8_t *p_supplemental_buffer = (uint8_t *)malloc(supplemental_size);
    if (NULL == p_supplemental_buffer) {
        printf("Couldn't allocate supplemental buffer\n");
        goto CLEANUP;
    }
    memset(p_supplemental_buffer, 0, supplemental_size);

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    int32_t ret = dcap_verify_quote(
        handle,
        p_quote_buffer,
        quote_size,
        &collateral_expiration_status,
        &quote_verification_result,
        supplemental_size,
        p_supplemental_buffer
        );

    if (0 != ret) {
        printf( "Error in dcap_verify_quote.\n");
        goto CLEANUP;
    }

    if (collateral_expiration_status != 0) {
        printf("the verification collateral has expired\n");
    }

    switch (quote_verification_result) {
        case SGX_QL_QV_RESULT_OK:
            printf("Succeed to verify the quote!\n");
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("WARN: App: Verification completed with Non-terminal result: %x\n",
                   quote_verification_result);
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            printf("\tError: App: Verification completed with Terminal result: %x\n",
                   quote_verification_result);
            goto CLEANUP;
    }

    printf("DCAP verify quote successfully\n");

CLEANUP:
    if (NULL != quote_buffer) {
        free(quote_buffer);
    }

    if (NULL != p_supplemental_buffer) {
        free(p_supplemental_buffer);
    }

    dcap_quote_close(handle);
    return 0;
}