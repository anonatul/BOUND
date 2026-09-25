# Run one BOUND ledger node on this Windows device and auto-join it.
#
#   .\scripts\start_node.ps1 -NodeId laptopB -Port 9101 -CoordinatorUrl http://192.168.50.10:8000
#
# Values may also come from environment variables (BOUND_NODE_ID,
# BOUND_NODE_PORT, BOUND_COORDINATOR_URL), so running the script with no
# arguments works after setting them.
#
# The node generates its ML-DSA-65 keypair on first start and keeps the private
# key on this device only. It announces itself to the coordinator, which adds it
# as a member witness. No internet needed; plain HTTP on the isolated LAN.
param(
    [string]$NodeId = "",
    [int]$Port = 0,
    [string]$CoordinatorUrl = ""
)

$ErrorActionPreference = "Stop"

if (-not $NodeId) { $NodeId = $env:BOUND_NODE_ID }
if (-not $NodeId) { throw "Set -NodeId <name> (or `$env:BOUND_NODE_ID) for this device." }
if ($Port -le 0) { $Port = if ($env:BOUND_NODE_PORT) { [int]$env:BOUND_NODE_PORT } else { 9101 } }
if (-not $CoordinatorUrl) { $CoordinatorUrl = $env:BOUND_COORDINATOR_URL }

Set-Location (Join-Path $PSScriptRoot "..")

$env:BOUND_NODE_ID = $NodeId
$env:BOUND_NODE_PORT = "$Port"
if (-not $env:BOUND_LEDGER_ROOT) {
    $env:BOUND_LEDGER_ROOT = Join-Path $PWD "ledger-lan"
}
$env:BOUND_COORDINATOR_URL = $CoordinatorUrl
New-Item -ItemType Directory -Force -Path (Join-Path $env:BOUND_LEDGER_ROOT $NodeId) | Out-Null

if ($CoordinatorUrl) {
    Write-Host "Starting ledger node '$NodeId' on 0.0.0.0:$Port, joining $CoordinatorUrl"
} else {
    Write-Host "Starting ledger node '$NodeId' on 0.0.0.0:$Port (no coordinator set: not auto-joining)"
}
Write-Host "  data dir : $env:BOUND_LEDGER_ROOT\$NodeId (private key stays local)"

uv run uvicorn backend.app.ledger.node_agent:app --host 0.0.0.0 --port $Port
