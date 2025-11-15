#!/usr/bin/env bash
set -e

IMAGE_NAME="cmcaas-server:"

if [ -e /dev/sgx_enclave ] && [ -e /dev/sgx_provision ]; then
    echo "[+] Detected SGX devices, running in non-privileged mode..."
    docker run -it --device /dev/sgx_enclave --device /dev/sgx_provision -p 8080:8080 "$IMAGE_NAME:latest"
else
    echo "[!] SGX device files not found. Running in simulation mode..."
    docker run -it -p 8080:8080 "$IMAGE_NAME:sim"
fi
