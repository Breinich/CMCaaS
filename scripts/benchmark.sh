#!/bin/bash
set -e

# Usage: ./benchmark.sh --mode <enclave|bare> [--log <path_to_server_log>]

MODE=""
LOG_FILE=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --mode) MODE="$2"; shift ;; # enclave or bare
    --log) LOG_FILE="$2"; shift ;;
    *) echo "Unknown parameter: $1"; exit 1 ;;
  esac
  shift
done

if [ -z "$MODE" ]; then
    echo "Error: --mode is required"
    exit 1
fi

# --- Setup Paths ---
BASE_DIR=$(pwd)
DATA_DIR="$BASE_DIR/data"
CLIENT_DIR="$BASE_DIR/src/client"
ENCLAVE_DIR="$BASE_DIR/src/enclave"
TARGET_FILE="$DATA_DIR/test.zip"
BACKUP_FILE="$DATA_DIR/test.zip.bak"

# --- 1. Identify Inputs ---
# Find all zip files in data dir
# We assume any .zip file currently in data/ is a valid input benchmark file
FILES=("$DATA_DIR"/*.zip)
NUM_FILES=${#FILES[@]}

if [ "$NUM_FILES" -eq 0 ]; then
    echo "Error: No .zip files found in $DATA_DIR"
    exit 1
fi

echo "[Benchmark] Mode: $MODE"
echo "[Benchmark] Found $NUM_FILES input file(s):"
printf '  - %s\n' "${FILES[@]}" | xargs -n 1 basename

# --- 2. Backup Target ---
# The clients are hardcoded to look for "test.zip" (or receive it as arg).
# We will swap files to this location. We back up the original if it exists.
if [ -f "$TARGET_FILE" ]; then
    cp "$TARGET_FILE" "$BACKUP_FILE"
fi

cleanup() {
    # Restore the original test.zip
    if [ -f "$BACKUP_FILE" ]; then
        mv "$BACKUP_FILE" "$TARGET_FILE"
    else
        rm -f "$TARGET_FILE"
    fi
}
trap cleanup EXIT

TOTAL_TIME=0
ITERATION=0

# --- 3. Loop Over Files ---
for input_file in "${FILES[@]}"; do
    ITERATION=$((ITERATION+1))
    FILENAME=$(basename "$input_file")

    # Skip the backup file if it was caught by the glob (unlikely with .bak extension but good practice)
    if [[ "$FILENAME" == "test.zip.bak" ]]; then continue; fi

    echo "--------------------------------------------------"
    echo "[Run $ITERATION/$NUM_FILES] Processing: $FILENAME"

    if [[ "$FILENAME" != "test.zip" ]]; then
        # Swap content to target
        cp "$input_file" "$TARGET_FILE"
    fi

    TIME_LOG=""

    if [ "$MODE" == "enclave" ]; then
        if [ -z "$LOG_FILE" ]; then
            echo "Error: --log <path> is required for enclave mode."
            exit 1
        fi

        # Mark log position
        START_LINE=$(wc -l < "$LOG_FILE")

        # Run RemoteClient
        pushd "$CLIENT_DIR" > /dev/null
        # RemoteClient defaults to ../../data/test.zip if no args provided
        java RemoteClient
        popd > /dev/null

        # Parse Logs
        NEW_LOGS=$(tail -n +$((START_LINE+1)) "$LOG_FILE")
        TIME_LOG=$(echo "$NEW_LOGS" | grep "CPU time used by verification process" | tail -n 1)

    elif [ "$MODE" == "bare" ]; then
        # Prepare directory for BareRunner (it reads from /tmp/input inside its container view)
        docker exec -it cmcaas-server mkdir -p /tmp/input
        docker cp "$TARGET_FILE" cmcaas-server:/tmp/input/test.zip

        BARE_LOG="/tmp/bare_${ITERATION}.log"

        # Start Runner in the container in background
        pushd "$ENCLAVE_DIR" > /dev/null
        docker exec -it cmcaas-server java BareRunner 6000 > "$BARE_LOG" 2>&1 &
        RUNNER_PID=$!
        popd > /dev/null

        sleep 2

        # Run Client in the container
        pushd "$CLIENT_DIR" > /dev/null
        docker exec -it cmcaas-server java BareClient 6000 test.zip
        popd > /dev/null

        wait $RUNNER_PID || true

        TIME_LOG=$(cat "$BARE_LOG" | grep "CPU time used by verification process" | tail -n 1)
        rm "$BARE_LOG"
    fi

    # --- Extract Time ---
    if [ -z "$TIME_LOG" ]; then
        echo "Error: Could not find CPU time in logs."
        exit 1
    fi

    MS=$(echo "$TIME_LOG" | grep -o '[0-9]\+')
    echo "  > Duration: $MS ms"
    TOTAL_TIME=$((TOTAL_TIME + MS))

done

# --- 4. Stats ---
AVG_TIME=$((TOTAL_TIME / ITERATION))
echo "=================================================="
echo "[Result] $MODE Mode Average CPU Time: $AVG_TIME ms (Samples: $ITERATION)"
echo "stats_avg_time=$AVG_TIME" >> "$GITHUB_OUTPUT"