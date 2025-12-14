#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_ql_lib_common.h>
#include <sgx_quote_3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

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

    // --- STEP 1: VERIFY NONCE (REPORT DATA) ---
    // We expect the enclave to have done: ReportData = SHA256(Nonce)
    // So we calculate SHA256(Nonce) here and compare.

    unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)nonce, strlen(nonce), calculated_hash);

    // Cast buffer to quote structure to access report body
    sgx_quote3_t *p_quote = (sgx_quote3_t *)quote_buffer;
    sgx_report_body_t *p_rep_body = (sgx_report_body_t *)(&p_quote->report_body);

    // Compare first 32 bytes of report data
    if (memcmp(p_rep_body->report_data.d, calculated_hash, SHA256_DIGEST_LENGTH) != 0) {
        printf("\n   [FAILURE] INTEGRITY CHECK FAILED!\n");
        printf("             The quote does NOT match the provided nonce.\n");
        printf("             This might be a replay attack or the enclave used different data.\n");
        free(quote_buffer);
        return 1;
    }
    printf("   [PASS] Nonce matches Quote Report Data (SHA256).\n");

    // --- STEP 2: VERIFY INTEL SIGNATURE ---
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t supplemental_size = 0;
    sgx_qv_get_quote_supplemental_data_size(&supplemental_size);
    uint8_t *p_supplemental_data = (uint8_t*)malloc(supplemental_size);

    printf("   [>] Contacting Intel PCCS...\n");
    quote3_error_t dcap_ret = sgx_qv_verify_quote(
        quote_buffer, (uint32_t)quote_size, NULL,
        time(NULL), &collateral_expiration_status, &quote_verification_result,
        NULL, supplemental_size, p_supplemental_data
    );

    if (dcap_ret != SGX_QL_SUCCESS) {
        printf("   [!] Error: DCAP Library failed (0x%04x). Check PCCS connection.\n", dcap_ret);
        return 1;
    }

    switch (quote_verification_result) {
        case SGX_QL_QV_RESULT_OK:
            printf("\n   [SUCCESS] QUOTE IS VALID, SECURE, AND FRESH.\n");
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("\n   [WARNING] QUOTE VALID (FRESH), BUT PLATFORM OUT OF DATE (0x%x)\n", quote_verification_result);
            break;
        default:
            printf("\n   [FAILURE] VERIFICATION FAILED (0x%x)\n", quote_verification_result);
            return 1;
    }

    free(quote_buffer);
    free(p_supplemental_data);
    return 0;
}