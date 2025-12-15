#!/bin/bash
set -e

data=$1
nonce=$2

rm -rf occlum_instance && occlum new occlum_instance
cd /app/src/client/occlum_instance
copy_bom -f ../dcap.yaml --root image --include-dir /opt/occlum/etc/template
occlum build

occlum run /bin/verification "$data" "$nonce"