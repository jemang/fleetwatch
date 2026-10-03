#!/bin/sh
set -eu
# FAKE_PVE=1 makes this container look like a Proxmox node: a stand-in API
# runs beside the agent and /etc/pve exists.
PVE_FLAGS=""
if [ "${FAKE_PVE:-}" = "1" ]; then
  fakepve &
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f /etc/pve/pve-root-ca.pem ] && break; sleep 0.3; done
  PVE_FLAGS="--pve-token-id fleetwatch@pve!agent --pve-token-secret fake-secret"
fi
# The config lives on a volume, so a restarted container does not enroll twice.
if [ ! -f /etc/fleetwatch/agent.yaml ]; then
  # shellcheck disable=SC2086
  fleetwatch-agent enroll --hub http://hub:8080 --token "$ENROLL_TOKEN" --allow-insecure-http $PVE_FLAGS
fi
exec fleetwatch-agent run
