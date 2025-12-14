#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_quote_3.h"
#include "sgx_urts.h"
#include "sgx_pce.h"
#include "sgx_error.h"

#include "occlum_dcap.h"

static const int mod_table[] = {0, 2, 1};

char* base64_encode(const uint8_t* data, size_t input_length) {
    const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char padding_character = '=';
    size_t output_length = 4 * ((input_length + 2) / 3);

    char* encoded_data = (char*)malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }

    for (size_t i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = padding_character;

    encoded_data[output_length] = '\0';
    return encoded_data;
}

// nonce should be a 32B string
void main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nonce_string>\n", argv[0]);
        exit(1);
    }

    int exit_code = 0;

    char *nonce = "test nonce string for quote"; //argv[1];
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
    memcpy(report_data.d, nonce, strlen(nonce));

    // Get the Quote
    ret = dcap_generate_quote(handle, p_quote_buffer, &report_data);
    if (0 != ret) {
        printf( "Error in dcap_generate_quote.\n");
        exit_code = 1;
        goto CLEANUP;
    }

    char* b64_quote = base64_encode(p_quote_buffer, quote_size);
    printf("%s", b64_quote);
    goto CLEANUP;

CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }

    if (NULL != p_supplemental_buffer) {
        free(p_supplemental_buffer);
    }

    dcap_quote_close(handle);

    exit(exit_code);
}