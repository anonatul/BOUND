# Run one BOUND ledger node on this Windows device.
#
#   .\scripts\start_node.ps1 -NodeId node3 -Port 9103
#
# The node generates its ML-DSA-65 keypair on first start and keeps the private
# key on this device only (under .\ledger-lan\<node_id>\). No internet needed;
# plain HTTP on the isolated LAN is intentional.
param(
    [Parameter(Mandatory = $true)][string]$NodeId,
    [int]$Port = 9103
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$env:BOUND_NODE_ID = $NodeId
if (-not $env:BOUND_LEDGER_ROOT) {
    $env:BOUND_LEDGER_ROOT = Join-Path $PWD "ledger-lan"
}
New-Item -ItemType Directory -Force -Path (Join-Path $env:BOUND_LEDGER_ROOT $NodeId) | Out-Null

Write-Host "Starting ledger node '$NodeId' on 0.0.0.0:$Port"
Write-Host "  data dir : $env:BOUND_LEDGER_ROOT\$NodeId (private key stays local)"
Write-Host "  public   : http://<this-device-ip>:$Port/health"

uv run uvicorn backend.app.ledger.node_agent:app --host 0.0.0.0 --port $Port
