#!/usr/bin/env bash
# Run one BOUND ledger node on this device and auto-join it to the ledger.
#
#   BOUND_NODE_ID=node1 BOUND_NODE_PORT=9101 \
#   BOUND_COORDINATOR_URL=http://192.168.50.10:8000 ./scripts/start_node.sh
#
# The node generates its ML-DSA-65 keypair on first start and keeps the private
# key on this device only. It announces itself (id + public key) to the
# coordinator, which adds it as a member witness. No uplink needed.
set -euo pipefail

cd "$(dirname "$0")/.."

NODE_ID="${BOUND_NODE_ID:?set BOUND_NODE_ID, e.g. node1}"
PORT="${BOUND_NODE_PORT:-9101}"
COORDINATOR_URL="${BOUND_COORDINATOR_URL:-}"
# node_agent appends /<node_id> to this root, so all nodes can share one root.
DATA_DIR="${BOUND_LEDGER_ROOT:-$PWD/ledger-lan}"

mkdir -p "$DATA_DIR"

if [ -n "$COORDINATOR_URL" ]; then
  echo "Starting ledger node '$NODE_ID' on 0.0.0.0:$PORT, joining $COORDINATOR_URL"
else
  echo "Starting ledger node '$NODE_ID' on 0.0.0.0:$PORT (no coordinator set: not auto-joining)"
fi
echo "  data dir : $DATA_DIR/$NODE_ID (private key stays local)"

export BOUND_NODE_ID="$NODE_ID"
export BOUND_NODE_PORT="$PORT"
export BOUND_LEDGER_ROOT="$DATA_DIR"
export BOUND_COORDINATOR_URL="$COORDINATOR_URL"
exec uv run uvicorn backend.app.ledger.node_agent:app --host 0.0.0.0 --port "$PORT"
