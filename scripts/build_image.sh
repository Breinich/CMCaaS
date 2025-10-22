#!/usr/bin/env bash
set -e

IMAGE_NAME="cmcaas-server:latest"

echo "[+] Building CMCaaS Docker image..."
docker build -t $IMAGE_NAME .

echo "[+] CMCaaS image built successfully: $IMAGE_NAME"
