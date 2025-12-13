#!/bin/bash
set -e

# --- CONFIGURATION ---
# Replace with your public PCCS URL if clients are external
PCCS_URL="https://localhost:8081/sgx/certification/v4/"

# Check arguments
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: sudo ./verify_quote.sh <BASE64_QUOTE> <NONCE>"
    echo "Example: sudo ./verify_quote.sh AwM...== my-random-nonce-123"
    exit 1
fi

QUOTE_STRING=$1
NONCE_STRING=$2

echo "============================================================"
echo "   Intel SGX DCAP Quote Verifier (Secure w/ Nonce)"
echo "============================================================"

# 1. INSTALL DEPENDENCIES
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./verify_quote.sh ...)"
  exit 1
fi

if ! grep -q "download.01.org" /etc/apt/sources.list.d/intel-sgx.list 2>/dev/null; then
    echo "[+] Adding Intel SGX repository..."
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
    apt-get update -qq
fi

# We add 'libssl-dev' for SHA256 calculation
apt-get install -y -qq libsgx-dcap-quote-verify-dev libsgx-dcap-default-qpl build-essential libssl-dev > /dev/null

# 2. CONFIGURE PCCS
mkdir -p /etc
cat <<EOF > /etc/sgx_default_qcnl.conf
{
  "pccs_url": "$PCCS_URL",
  "use_secure_cert": false
}
EOF

# 3. CREATE C SOURCE CODE
cat <<'EOF' > client_verifier.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_ql_lib_common.h>
#include <sgx_quote_3.h> // For parsing the quote structure

// Base64 Decode Helper
static const unsigned char base64_table[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
};

unsigned char *base64_decode(const char *src, size_t len, size_t *out_len) {
    unsigned char *out, *pos, block[4];
    size_t i, count, pad = 0;
    if (len >= 4 && src[len - 1] == '=') pad++;
    if (len >= 4 && src[len - 2] == '=') pad++;
    count = (len / 4) * 3 - pad;
    out = (unsigned char *)malloc(count);
    if (out == NULL) return NULL;
    pos = out;
    for (i = 0; i < len; i += 4) {
        block[0] = base64_table[(unsigned char)src[i]];
        block[1] = base64_table[(unsigned char)src[i + 1]];
        block[2] = base64_table[(unsigned char)src[i + 2]];
        block[3] = base64_table[(unsigned char)src[i + 3]];
        if ((block[0] | block[1] | block[2] | block[3]) == 64) { free(out); return NULL; }
        *pos++ = (block[0] << 2) | (block[1] >> 4);
        if (pos < out + count) *pos++ = (block[1] << 4) | (block[2] >> 2);
        if (pos < out + count) *pos++ = (block[2] << 6) | block[3];
    }
    *out_len = count;
    return out;
}

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;

    char *nonce = argv[2];
    size_t quote_size = 0;
    uint8_t *quote_buffer = base64_decode(argv[1], strlen(argv[1]), &quote_size);
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
EOF

# 4. COMPILE (Link against OpenSSL crypto library)
echo "[+] Compiling..."
gcc client_verifier.c -o client_verifier -lsgx_dcap_quoteverify -lcrypto -w

# 5. RUN
echo "[+] Running verification..."
./client_verifier "$QUOTE_STRING" "$NONCE_STRING"

rm client_verifier.c
echo "============================================================"