#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'

show_usage() {
    echo "Usage: $0 verifier <ENCLAVE_ID>"
    echo "Example: $0 verifier 001"
    exit 1
}

check_file_exist() {
    file=$1
    if [ ! -f "${file}" ]; then
        echo "Error: cannot stat file '${file}'"
        echo "Please compile VerifierRunner.java first"
        exit 1
    fi
}

init_instance() {
    enclave_id=$1
    instance_name="occlum_verifier_${enclave_id}"

    rm -rf "${instance_name}" && mkdir "${instance_name}"
    cd "${instance_name}"
    occlum init

    # Tune Occlum.json for JVM
    new_json="$(jq '.resource_limits.user_space_size = "1MB" |
                    .resource_limits.user_space_max_size = "6600MB" |
                    .resource_limits.kernel_space_heap_size = "1MB" |
                    .resource_limits.kernel_space_heap_max_size = "64MB" |
                    .resource_limits.max_num_of_threads = 64 |
                    .process.default_heap_size = "256MB" |
                    .entry_points = ["/usr/lib/jvm/java-21-openjdk-amd64/bin/java"] |
                    .env.default = [
                    "LD_LIBRARY_PATH=/usr/lib/jvm/java-21-openjdk-amd64/lib/server:/usr/lib/jvm/java-21-openjdk-amd64/lib:/lib/x86_64-linux-gnu:/opt/occlum/glibc/lib",
                    "JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64",
                    "PATH=/usr/lib/jvm/java-21-openjdk-amd64/bin:/bin:/usr/bin:/usr/local/bin"
                    ]' Occlum.json)"
    echo "${new_json}" > Occlum.json
}


build_verifier() {
    # Copy JVM and VerifierRunner class file into Occlum instance and build
    rm -rf image
    copy_bom -f /app/src/enclave/verifier.yaml --root image --include-dir /opt/occlum/etc/template
    occlum build
}

run_verifier() {
    enclave_id=$1
    verifier_class=/app/src/enclave/VerifierRunner.class

    check_file_exist ${verifier_class}
    init_instance "${enclave_id}"
    build_verifier

    echo -e "${BLUE}occlum run JVM VerifierRunner (enclave id=${enclave_id})${NC}"
    occlum run /usr/lib/jvm/java-21-openjdk-amd64/bin/java -Xmx512m -XX:-UseCompressedOops -XX:MaxMetaspaceSize=64m \
    -Dos.name=Linux -Djdk.lang.Process.launchMechanism=posix_spawn VerifierRunner "${enclave_id}"
}

# --- main ---
arg=$1
enclave_id=$2

if [ "$arg" != "verifier" ] || [ -z "$enclave_id" ]; then
    show_usage
fi

run_verifier "${enclave_id}"
