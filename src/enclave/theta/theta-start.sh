#!/bin/bash
set -e

scriptdir=$(dirname "$(realpath "$0")")
IN=$1

# Configurable heap: set THETA_XMX environment variable to override.
DEFAULT_XMX="14210m"

# Determine Xmx
if [ -n "${THETA_XMX}" ]; then
    XMX="${THETA_XMX}"
    XMX_REASON="env THETA_XMX"
else
    XMX="${DEFAULT_XMX}"
    XMX_REASON="default"
fi

export VERIFIER_NAME=Theta
export VERIFIER_VERSION=6.8.6

if [ "$1" == "--version" ]; then
    LD_LIBRARY_PATH=$scriptdir/lib:${LD_LIBRARY_PATH} java -Xmx"${XMX}" -Djdk.lang.Process.launchMechanism=posix_spawn -jar "$scriptdir"/theta.jar --version || echo $VERIFIER_VERSION
    exit
fi

remove_property() {
    local args=()
    local skip=0
    for arg in "$@"; do
        if [ "$skip" -eq 1 ]; then
            echo "$arg" > .property
            skip=0
            continue
        fi
        if [ "$arg" == "--property" ]; then
            skip=1
            continue
        fi
        args+=("$arg")
    done
    echo "${args[@]}"
}

modified_args=$(remove_property "${@:2}")
property=$(cat .property && rm .property)
echo "Verifying input '$IN' with property '$property' using arguments '$modified_args'"

transformed_property="$property"

echo "Using Java heap -Xmx=${XMX} (${XMX_REASON})"
echo LD_LIBRARY_PATH="$scriptdir"/lib:"${LD_LIBRARY_PATH}" java -Xmx"${XMX}" -Djdk.lang.Process.launchMechanism=posix_spawn -jar "$scriptdir"/theta.jar "$modified_args" --input "$IN" --property "$transformed_property" --smt-home "$scriptdir"/solvers
LD_LIBRARY_PATH="$scriptdir"/lib:"${LD_LIBRARY_PATH}" java -Xmx"${XMX}" -Djdk.lang.Process.launchMechanism=posix_spawn -jar "$scriptdir"/theta.jar "$modified_args" --input "$IN" --property "$transformed_property" --smt-home "$scriptdir"/solvers

if [ "$(basename "$property")" == "termination.prp" ]; then
    echo "Not yet mapping witnesses from '$transformed_property' to '$property', hoping for the best"
elif [ "$(basename "$property")" == "no-overflow.prp" ]; then
    echo "Not yet mapping witnesses from '$transformed_property' to '$property', hoping for the best"
fi
