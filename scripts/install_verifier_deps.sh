#!/bin/bash
set -e

PCCS_URL="https://api.trustedservices.intel.com/sgx/certification/v4/"

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
echo "[+] Configuring PCCS..."
export SGX_QCNL_CONF_FILE=/etc/sgx_default_qcnl.conf
mkdir -p /etc
cat <<EOF > /etc/sgx_default_qcnl.conf
{
  "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/"
  ,"use_secure_cert": true
  ,"retry_times": 6
  ,"retry_delay": 10
  ,"pck_cache_expire_hours": 168
  ,"verify_collateral_cache_expire_hours": 168
  ,"local_cache_only": false
}
EOF

echo "[+] Compiling..."
gcc ../src/client/verification.c -o ../src/client/verification -lsgx_dcap_quoteverify -lcrypto -w

echo "[+] Verifier dependencies installed successfully."