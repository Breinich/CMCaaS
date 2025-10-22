#!/usr/bin/env bash
set -e

IMAGE_NAME="cmcaas-server:latest"

if [ -e /dev/sgx_enclave ] && [ -e /dev/sgx_provision ]; then
    echo "[+] Detected SGX devices, running in non-privileged mode..."
    docker run -it --device /dev/sgx/enclave --device /dev/sgx/provision -p 8080:8080 $IMAGE_NAME
else
    echo "[!] SGX device files not found. Running in privileged fallback mode..."
    docker run -it --privileged -v /dev/sgx:/dev/sgx -p 8080:8080 $IMAGE_NAME
fi
