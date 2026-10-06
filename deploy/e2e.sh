#!/usr/bin/env bash
# End-to-end check: enroll one agent container (host name e2e-agent), see it
# online, stop it, see it offline, restart it, see that it is still one row.
# Only the e2e-agent row is read, so other hosts on the same Hub do not matter.
# Containers and volumes are left in place.
set -euo pipefail
cd "$(dirname "$0")"

export FLEETWATCH_ADMIN_PASSWORD="${FLEETWATCH_ADMIN_PASSWORD:-e2e-password}"
# The Hub from the main file built from this checkout, the test agent from the simulation file.
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.build.yml -f docker-compose.test.yml"
BASE="http://localhost:${FLEETWATCH_PORT:-8080}"
JAR="$(mktemp)"

# agent_status prints the status of every row named e2e-agent, one per line.
agent_status() {
  perl -ne 'while (/<tr id="host-\d+"[^>]*><td class="host" data-v="e2e-agent">.*?data-status="(\w+)"/g) { print "$1\n" }'
}

wait_status() { # wait_status <online|offline> <seconds>
  local want="$1" limit="$2" start=$SECONDS page
  while (( SECONDS - start <= limit )); do
    page="$(curl -fsS -b "$JAR" "$BASE/hosts" || true)"
    if [ "$(agent_status <<<"$page")" = "$want" ]; then
      echo "host is $want after $(( SECONDS - start ))s"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: host is not $want within ${limit}s"
  exit 1
}

[ -f ../release/signing-key.pem ] || { echo "FAIL: no signing key. Run 'make release-key' once (see README)."; exit 1; }
$COMPOSE up -d --build hub
for _ in $(seq 30); do
  curl -fsS -o /dev/null "$BASE/login" && break
  sleep 1
done
curl -fsS -o /dev/null -c "$JAR" -d "password=$FLEETWATCH_ADMIN_PASSWORD" "$BASE/login"

FRAGMENT="$(curl -fsS -b "$JAR" -H 'HX-Request: true' -X POST "$BASE/servers/enroll-token")"
TOKEN="$(sed -n 's#.*/install/\([A-Za-z0-9_-]*\) .*#\1#p' <<<"$FRAGMENT" | head -1)"
[ -n "$TOKEN" ] || { echo "FAIL: no enrollment token in the Add Server fragment"; exit 1; }

# The Hub must hand out the signed agent files and an install script for the token.
curl -fsS -o /dev/null "$BASE/dl/SHA256SUMS.sig" || { echo "FAIL: the Hub does not serve the signed agent files"; exit 1; }
curl -fsS "$BASE/install/$TOKEN" | grep -q '^main "\$@"$' || { echo "FAIL: no install script for a fresh token"; exit 1; }

ENROLL_TOKEN="$TOKEN" $COMPOSE up -d --build agent-test
wait_status online 30

$COMPOSE stop agent-test
wait_status offline 50

$COMPOSE start agent-test
wait_status online 30

PAGE="$(curl -fsS -b "$JAR" "$BASE/hosts")"
ROWS="$(agent_status <<<"$PAGE" | wc -l | tr -d ' ')"
[ "$ROWS" = "1" ] || { echo "FAIL: expected 1 e2e-agent row after restart, found $ROWS"; exit 1; }

echo "E2E PASS. Hub is at $BASE (password: $FLEETWATCH_ADMIN_PASSWORD). Containers and data are left running."
