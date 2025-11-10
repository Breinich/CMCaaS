#!/usr/bin/env bash
set -e

IMAGE_NAME="cmcaas-server"

echo "[+] Building CMCaaS Docker image..."
docker build -t "$IMAGE_NAME:latest" .

echo "[+] Building CMCaaS Simulation Docker image..."
docker build -f Dockerfile.sim -t "$IMAGE_NAME:sim" .

echo "[+] CMCaaS Docker images built successfully:"
echo "    - $IMAGE_NAME:latest"
echo "    - $IMAGE_NAME:sim"

