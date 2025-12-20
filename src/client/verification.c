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

const unsigned char MRENCLAVE[] = {
    0xe0, 0xcf, 0x24, 0x74, 0xf0, 0x50, 0x02, 0xbc,
    0xf9, 0x7b, 0x21, 0xd3, 0xa0, 0x36, 0x36, 0x20,
    0xd2, 0x25, 0xc1, 0x35, 0x83, 0x11, 0x55, 0xe7,
    0x1b, 0x7c, 0x4d, 0xc4, 0xc7, 0xf5, 0xa2, 0xe3
};

const unsigned char MRSIGNER[] = {
    0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14,
    0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43,
    0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c,
    0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e
};

unsigned char* base64_decode(const char* encoded_data, uint32_t* output_length) {
    BIO *bio, *b64;
    size_t input_length = strlen(encoded_data);

    size_t max_len = (input_length * 3) / 4 + 1;
    unsigned char* decoded_data = (unsigned char*)malloc(max_len);
    if (decoded_data == NULL) return NULL;

    bio = BIO_new_mem_buf(encoded_data, -1);
    b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    *output_length = BIO_read(bio, decoded_data, input_length);
    BIO_free_all(bio);

    return decoded_data;
}

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;

    char *nonce = argv[2];
	int exit_code = 0;

    void* handle;
	handle = dcap_quote_open();
    uint32_t quote_size = 0;

    uint8_t *quote_buffer = base64_decode(argv[1], &quote_size);
    if (!quote_buffer) { printf("Invalid Base64\n"); return 1; }

    sgx_quote3_t *p_quote = (sgx_quote3_t *)quote_buffer;
    sgx_report_body_t *p_rep_body = (sgx_report_body_t *)(&p_quote->report_body);
    sgx_report_data_t *p_rep_data = (sgx_report_data_t *)(&p_rep_body->report_data);

    size_t nonce_len = strlen(nonce);
    if (nonce_len > sizeof(p_rep_data->d)) {
        nonce_len = sizeof(p_rep_data->d); // Truncate if too long
    }

    if (memcmp((void *)p_rep_data->d, (void *)nonce, nonce_len) != 0) {
        printf("Error: Nonce mismatch in report data.\n");
        exit_code = -1;
        goto CLEANUP;
    }

    if (memcmp((void *)p_rep_body->mr_enclave.m, (void *)MRENCLAVE, sizeof(MRENCLAVE)) != 0) {
        printf("Error: MRENCLAVE mismatch in report data.\n");
        printf("Expected MRENCLAVE: ");
        for (size_t i = 0; i < sizeof(MRENCLAVE); i++) {
            printf("%02x", MRENCLAVE[i]);
        }
        printf("\nActual MRENCLAVE:   ");
        for (size_t i = 0; i < sizeof(p_rep_body->mr_enclave.m); i++) {
            printf("%02x", p_rep_body->mr_enclave.m[i]);
        }
        printf("\n");
        exit_code = -1;
        goto CLEANUP;
    }

    if (memcmp((void *)p_rep_body->mr_signer.m, (void *)MRSIGNER, sizeof(MRSIGNER)) != 0) {
        printf("Error: MRSIGNER mismatch in report data.\n");
        printf("Expected MRSIGNER: ");
        for (size_t i = 0; i < sizeof(MRSIGNER); i++) {
            printf("%02x", MRSIGNER[i]);
        }
        printf("\nActual MRSIGNER:   ");
        for (size_t i = 0; i < sizeof(p_rep_body->mr_signer.m); i++) {
            printf("%02x", p_rep_body->mr_signer.m[i]);
        }
        printf("\n");
        exit_code = -1;
        goto CLEANUP;
    }

    uint32_t supplemental_size = dcap_get_supplemental_data_size(handle);
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
        quote_buffer,
        quote_size,
        &collateral_expiration_status,
        &quote_verification_result,
        supplemental_size,
        p_supplemental_buffer
        );

    if (0 != ret) {
        printf( "Error in dcap_verify_quote.\nReturn code: %d\n", ret);
		exit_code = ret;
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
    return exit_code;
}