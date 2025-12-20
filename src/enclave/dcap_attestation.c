#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "sgx_quote_3.h"
#include "sgx_urts.h"
#include "sgx_pce.h"
#include "sgx_error.h"

#include "occlum_dcap.h"

char* base64_encode(const unsigned char* data, size_t input_length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    size_t output_length = 4 * ((input_length + 2) / 3);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, input_length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    char *encoded_data = (char *)malloc(bufferPtr->length + 1);
    if (encoded_data == NULL) {
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(encoded_data, bufferPtr->data, bufferPtr->length);
    encoded_data[bufferPtr->length] = '\0';

    BIO_free_all(bio);

    return encoded_data;
}

void main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nonce_string>\n", argv[0]);
        exit(1);
    }

    int exit_code = 0;
    char *nonce = argv[1];

    void *handle;
    uint32_t quote_size, supplemental_size;
    uint8_t *p_quote_buffer, *p_supplemental_buffer;
    sgx_quote3_t *p_quote;
    sgx_report_body_t *p_rep_body;
    sgx_report_data_t *p_rep_data;
    int32_t ret;

    handle = dcap_quote_open();
    quote_size = dcap_get_quote_size(handle);

    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        exit_code = 1;
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, quote_size);

    sgx_report_data_t report_data = { 0 };
    size_t nonce_len = strlen(nonce);
    if (nonce_len > sizeof(report_data.d)) {
        nonce_len = sizeof(report_data.d); // Truncate if too long
    }

    memcpy(report_data.d, nonce, nonce_len);

    ret = dcap_generate_quote(handle, p_quote_buffer, &report_data);
    if (0 != ret) {
        printf( "Error in dcap_generate_quote.\n");
        exit_code = 1;
        goto CLEANUP;
    }

    char* b64_quote = base64_encode(p_quote_buffer, quote_size);
    printf("%s", b64_quote);

    char* b64_mrenclave = base64_encode(
        ((sgx_quote3_t *)p_quote_buffer)->report_body.mr_enclave.m,
        sizeof(((sgx_quote3_t *)p_quote_buffer)->report_body.mr_enclave.m)
    );
    printf("\n%s", b64_mrenclave);)

    char* b64_mrsigner = base64_encode(
        ((sgx_quote3_t *)p_quote_buffer)->report_body.mr_signer.m,
        sizeof(((sgx_quote3_t *)p_quote_buffer)->report_body.mr_signer.m)
    );
    printf("\n%s", b64_mrsigner);
    goto CLEANUP;

CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }

    if (NULL != p_supplemental_buffer) {
        free(p_supplemental_buffer);
    }

    if (NULL != b64_quote) {
        free(b64_quote);
    }

    dcap_quote_close(handle);

    exit(exit_code);
}