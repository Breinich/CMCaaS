#!/usr/bin/env bash
set -e

SERVER_IMAGE="cmcaas-server"
ATTESTER_IMAGE="cmcaas-attester"

echo "[+] Building CMCaaS Docker image..."
docker build -t "$SERVER_IMAGE:latest" .

echo "[+] Building CMCaaS Simulation Docker image..."
docker build -f Dockerfile_sim -t "$SERVER_IMAGE:sim" .

echo "[+] Building enclave verifier Docker image..."
docker build -f Dockerfile_attester -t "$ATTESTER_IMAGE:latest" .

echo "[+] CMCaaS Docker images built successfully:"
echo "    - $SERVER_IMAGE:latest"
echo "    - $SERVER_IMAGE:sim"
echo "    - $ATTESTER_IMAGE:latest"


