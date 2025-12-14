#!/usr/bin/env bash
set -e

IMAGE_NAME="cmcaas-server"

echo "[+] Building CMCaaS Docker image..."
docker build -t "$IMAGE_NAME:latest" .

echo "[+] Building CMCaaS Simulation Docker image..."
docker build -f Dockerfile_sim -t "$IMAGE_NAME:sim" .

echo "[+] Building enclave verifier Docker image..."
docker build -f Dockerfile_verifier -t "cmcaas-verifier:latest" .

echo "[+] CMCaaS Docker images built successfully:"
echo "    - $IMAGE_NAME:latest"
echo "    - $IMAGE_NAME:sim"
echo "    - cmcaas-verifier:latest"


