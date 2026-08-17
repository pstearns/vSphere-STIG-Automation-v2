#!/bin/bash

# Ensure a collection number was provided
if [ -z "$1" ]; then
  echo "Error: You must provide a Collection ID."
  echo "Usage: $0 <collection_id>"
  echo "Example: $0 16"
  exit 1
fi

COLLECTION_ID=$1
BASE_DIR="/usr/share/stigs/orchestration_overlay/stigman-watcher"
ENV_FILE="/usr/share/stigs/orchestration_overlay/conf/stigman-watcher/collection_${COLLECTION_ID}.env"
INBOX_DIR="${BASE_DIR}/inboxes/coll_${COLLECTION_ID}"

# Verify the environment file exists
if [ ! -f "$ENV_FILE" ]; then
  echo "Error: Configuration file not found at ${ENV_FILE}"
  exit 1
fi

# Ensure the inbox directory exists
mkdir -p "$INBOX_DIR"

# 1. Global TLS bypass and Warning suppression for Node.js
export NODE_TLS_REJECT_UNAUTHORIZED=0
export NODE_NO_WARNINGS=1 # <-- ADD THIS LINE HERE TO SILENCE ALL RUNTIME WARNINGS

# 2. Tell the watcher to write its history file cleanly inside the specific collection inbox
export WATCHER_HISTORY_FILE="${INBOX_DIR}/watcher-history-col-${COLLECTION_ID}.yaml"

# 3. Load variables safely from the specific collection .env file
set -a
source <(grep -v '^#' "$ENV_FILE" | grep -v '^$' | tr -d '\r')
set +a

# 4. Change directory to the binary folder and run, explicitly targeting the inbox
cd "${BASE_DIR}/bin" || exit
echo "Starting scan for Collection ${COLLECTION_ID} in ${INBOX_DIR}..."

./stigman-watcher \
  -d \
  --mode scan \
  --one-shot \
  -p "$INBOX_DIR"