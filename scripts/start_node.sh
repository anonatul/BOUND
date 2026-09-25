#!/usr/bin/env bash
# Run one BOUND ledger node on this device.
#
#   BOUND_NODE_ID=node1 BOUND_NODE_PORT=9101 ./scripts/start_node.sh
#
# The node generates its ML-DSA-65 keypair on first start and keeps the private
# key on this device only (under $BOUND_LEDGER_ROOT/<node_id>/, chmod 600).
# No uplink is needed: plain HTTP on the isolated LAN is intentional.
set -euo pipefail

cd "$(dirname "$0")/.."

NODE_ID="${BOUND_NODE_ID:?set BOUND_NODE_ID, e.g. node1}"
PORT="${BOUND_NODE_PORT:-9101}"
# node_agent appends /<node_id> to this root, so all nodes can share one root.
DATA_DIR="${BOUND_LEDGER_ROOT:-$PWD/ledger-lan}"

mkdir -p "$DATA_DIR"

echo "Starting ledger node '$NODE_ID' on 0.0.0.0:$PORT"
echo "  data dir : $DATA_DIR (private key stays local)"
echo "  public   : http://<this-device-ip>:$PORT/health"

export BOUND_NODE_ID="$NODE_ID"
export BOUND_LEDGER_ROOT="$DATA_DIR"
exec uv run uvicorn backend.app.ledger.node_agent:app --host 0.0.0.0 --port "$PORT"
