#!/bin/bash
set -e

scriptdir=$(dirname "$(realpath "$0")")
IN=$1

# Configurable heap: set THETA_XMX environment variable to override.
DEFAULT_XMX="14210m"
FALLBACK_XMX="512m"
# If total system memory is below this threshold (KB), use fallback Xmx
MEM_THRESHOLD_KB=$((16*1024*1024)) # 16 GB

# Determine Xmx
if [ -n "${THETA_XMX}" ]; then
    XMX="${THETA_XMX}"
    XMX_REASON="env THETA_XMX"
else
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "${mem_kb}" -gt 0 ] && [ "${mem_kb}" -lt "${MEM_THRESHOLD_KB}" ]; then
        XMX="${FALLBACK_XMX}"
        XMX_REASON="low-memory detected (${mem_kb} KB)"
    else
        XMX="${DEFAULT_XMX}"
        XMX_REASON="default"
    fi
fi

export VERIFIER_NAME=Theta
export VERIFIER_VERSION=6.8.6

if [ "$1" == "--version" ]; then
    LD_LIBRARY_PATH=$scriptdir/lib java -Xmx"${XMX}" -jar "$scriptdir"/theta.jar --version || echo $VERIFIER_VERSION
    exit
fi

JAVA_VERSION=17
JAVA_FALLBACK_PATH="/usr/lib/jvm/java-$JAVA_VERSION-openjdk-amd64/bin/:/usr/lib/jvm/java-$JAVA_VERSION-openjdk/bin/:/usr/lib/jvm/java-$JAVA_VERSION/bin/"
grep -o "openjdk $JAVA_VERSION" <<< "$(java --version)" >/dev/null || export PATH="$JAVA_FALLBACK_PATH":$PATH
grep -o "openjdk $JAVA_VERSION" <<< "$(java --version)" >/dev/null || {
    echo "Could not set up openjdk-$JAVA_VERSION. Is the JRE/JDK installed?"
    exit 1
}

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

if [ "$(basename "$property")" == "termination.prp" ]; then
    transformed_property=$(dirname "$property")/unreach-call.prp
    echo "Mapping property '$property' to '$transformed_property'"
    TMPFILE=$(mktemp -p "$PWD")
    sed 's/__VERIFIER_assert/__OLD_VERIFIER_assert/g;s/reach_error/old_reach_error/g' "$IN" > "$TMPFILE"
    python3 "$scriptdir"/specification-transformation/src/specification-transformation.py --from-property termination --to-property reachability --algorithm InstrumentationOperator "$TMPFILE"
    #"$scriptdir"/offset.sh "$IN" "output/transformed_program.c" > witness-mapping.yml
    modified_args="$modified_args --input-file-for-witness $IN"
    IN="output/transformed_program.c"
    rm "$TMPFILE"
elif [ "$(basename "$property")" == "no-overflow.prp" ]; then
    transformed_property=$(dirname "$property")/unreach-call.prp
    echo "Mapping property '$property' to '$transformed_property'"
    TMPFILE=$(mktemp -p "$PWD")
    sed 's/__VERIFIER_assert/__OLD_VERIFIER_assert/g;s/reach_error/old_reach_error/g' "$IN" > "$TMPFILE"
    python3 "$scriptdir"/specification-transformation/src/specification-transformation.py --from-property no-overflow --to-property reachability --algorithm InstrumentationOperator "$TMPFILE"
    #"$scriptdir"/offset.sh "$IN" "output/transformed_program.c" > witness-mapping.yml
    modified_args="$modified_args --input-file-for-witness $IN"
    IN="output/transformed_program.c"
    rm "$TMPFILE"
else
    transformed_property="$property"
fi

echo "Using Java heap -Xmx=${XMX} (${XMX_REASON})"
echo LD_LIBRARY_PATH="$scriptdir"/lib java -Xmx"${XMX}" -jar "$scriptdir"/theta.jar "$modified_args" --input "$IN" --property "$transformed_property" --smt-home "$scriptdir"/solvers
LD_LIBRARY_PATH="$scriptdir"/lib java -Xmx"${XMX}" -jar "$scriptdir"/theta.jar "$modified_args" --input "$IN" --property "$transformed_property" --smt-home "$scriptdir"/solvers

if [ "$(basename "$property")" == "termination.prp" ]; then
    echo "Not yet mapping witnesses from '$transformed_property' to '$property', hoping for the best"
elif [ "$(basename "$property")" == "no-overflow.prp" ]; then
    echo "Not yet mapping witnesses from '$transformed_property' to '$property', hoping for the best"
fi
