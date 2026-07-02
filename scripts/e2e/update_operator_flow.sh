#!/usr/bin/env bash
# Operator smoke: propose and vote on an update via outbe-cli, assert status visibility,
# and check multi-node state-root parity. Uses the same gramine-mock TEE localnet
# harness as the S1–S7 e2e suite. Does not wait through the voting
# window or activation — those paths stay covered by in-memory Rust e2e tests.
#
# Env (optional):
#   E2E_REPO            repo root (default: repo containing this script)
#   E2E_NO_SUDO=1       run docker/process cleanup without sudo (Docker must be accessible)
#   E2E_NO_TEE=1        run localnet without Gramine TEE containers
#   E2E_VOTE_WINDOW_BLOCKS
#                       localnet vote window override (default: 6 blocks)
#   E2E_DIR / OUT_DIR    localnet data dir (default: fresh /tmp dir)
#   E2E_BIN             outbe-chain binary (default: target/debug/outbe-chain)
#   E2E_CLI             outbe-cli binary (default: target/debug/outbe-cli)
#   E2E_MOCK            outbe-tee-enclave-mock binary
#
# Requires: cast, jq, foundry (cast); docker unless E2E_NO_TEE=1; sudo unless E2E_NO_SUDO=1
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_REPO="${E2E_REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
[ -n "${HOME:-}" ] && export PATH="$PATH:$HOME/.foundry/bin"

E2E_NAME=UPDATE_OP_FLOW
E2E_DIR="${OUT_DIR:-$(mktemp -d /tmp/outbe-update-op.XXXXXX)}"
export OUT_DIR="$E2E_DIR"
source "$SCRIPT_DIR/lib.sh"

MIN_ACTIVATION_BUFFER=100
UPDATE_ADDR=0x000000000000000000000000000000000000EE0B
E2E_VOTE_WINDOW_BLOCKS="${E2E_VOTE_WINDOW_BLOCKS:-6}"

UPDATE_OP_FLOW_TEE=true

# For local run without sudo set sudo to a no-op function
case "${E2E_NO_SUDO:-}" in
  1|true|TRUE|yes|YES) sudo() { "$@"; } ;;
esac


case "${E2E_NO_TEE:-}" in
  1|true|TRUE|yes|YES)
    UPDATE_OP_FLOW_TEE=false
    ;;
esac

e2e_start() {
  if [ "$UPDATE_OP_FLOW_TEE" = true ]; then
    sudo env OUTBE_TEST_VOTING_WINDOW_BLOCKS="$E2E_VOTE_WINDOW_BLOCKS" \
      OUTBE_TEE_ENCLAVE=1 OUTBE_TEE_ENCLAVE_MOCK=1 OUTBE_TEE_SEAL=1 \
      OUTBE_TEE_ENCLAVE_BINARY="$E2E_MOCK" OUTBE_CHAIN_BINARY="$E2E_BIN" PATH="$PATH" \
      ./scripts/run-testnet.sh start "$E2E_DIR" >/tmp/e2e-start.log 2>&1
    local ok=false
    for _ in $(seq 1 18); do sleep 5; [ "$(e2e_bootstrapped)" = "true" ] && { ok=true; break; }; done
    e2e_assert "TEE chain bootstrapped" "$([ "$ok" = true ] && echo true || echo false)"
  else
    sudo env OUTBE_TEST_VOTING_WINDOW_BLOCKS="$E2E_VOTE_WINDOW_BLOCKS" \
      OUTBE_CHAIN_BINARY="$E2E_BIN" PATH="$PATH" \
      ./scripts/run-testnet.sh start "$E2E_DIR" >/tmp/e2e-start.log 2>&1
    local ok=false h
    for _ in $(seq 1 18); do
      sleep 5
      h=$(e2e_h 8545)
      [ "$h" != "dn" ] && { ok=true; break; }
    done
    e2e_assert "non-TEE chain RPC reachable" "$([ "$ok" = true ] && echo true || echo false)"
  fi
}

active_protocol_version() {
  local raw
  raw=$(cast call "$UPDATE_ADDR" 'getActiveVersion()(uint32)' --rpc-url "$RPC0" 2>/dev/null \
    | awk 'NF {print $1; exit}')
  if [[ "$raw" =~ ^0x ]]; then
    printf '%d\n' "$raw"
  else
    echo "$raw"
  fi
}

scheduled_update_field() {
  local field="$1"
  cast call "$UPDATE_ADDR" 'getScheduledUpdate(uint256)((uint256,uint32,uint64,bytes,uint8))' 1 \
    --rpc-url "$RPC0" 2>/dev/null \
    | tr -d '(),' \
    | awk -v field="$field" '
        {
          for (i = 1; i <= NF; i++) {
            values[++n] = $i
          }
        }
        END {
          if (field <= n) print values[field]
        }'
}

schedule_update_payload() {
  printf '{"version":%s,"activationHeight":%s,"info":"e2e update operator smoke"}' \
    "$VERSION" "$ACTIVATION"
}

run_update_propose() {
  "$E2E_CLI" \
    --private-key "$1" \
    --rpc-url "$RPC0" \
    vote propose \
    --target-module "$UPDATE_ADDR" \
    --payload "$PAYLOAD"
}

run_update_vote() {
  "$E2E_CLI" \
    --private-key "$1" \
    --rpc-url "$RPC0" \
    vote cast --proposal-id 1 --yes
}

wait_tx_success() {
  local tx_hash="$1"
  local label="$2"
  local tries="${3:-40}"
  local status
  for _ in $(seq 1 "$tries"); do
    status=$(cast receipt "$tx_hash" status --rpc-url "$RPC0" 2>/dev/null || echo dn)
    case "$status" in
      true|1|0x1)
        return 0
        ;;
      false|0|0x0)
        e2e_log "$label transaction reverted: $tx_hash"
        return 1
        ;;
    esac
    sleep 3
  done
  e2e_log "$label transaction not confirmed within timeout: $tx_hash"
  return 1
}

extract_tx_hash() {
  sed -n 's/.*[Tt]ransaction sent: \(0x[0-9a-fA-F]\{64\}\).*/\1/p' | head -1
}

extract_deadline() {
  echo "$1" | sed -n 's/.*deadline=\([0-9][0-9]*\).*/\1/p' | head -1
}

wait_height_gt() {
  local height="$1"
  local tries="${2:-80}"
  local h
  for _ in $(seq 1 "$tries"); do
    h=$(e2e_h 8545)
    if [ "$h" != "dn" ] && [ "$h" -gt "$height" ] 2>/dev/null; then
      echo "$h"
      return 0
    fi
    sleep 3
  done
  echo "$h"
  return 1
}

wait_vote_status() {
  local want="$1"
  local tries="${2:-60}"
  for _ in $(seq 1 "$tries"); do
    STATUS=$("$E2E_CLI" --rpc-url "$RPC0" vote status --proposal-id 1 2>&1 || true)
    if echo "$STATUS" | grep -q "status=$want"; then
      return 0
    fi
    sleep 3
  done
  return 1
}

wait_active_version() {
  local want="$1"
  local tries="${2:-180}"
  local got
  for _ in $(seq 1 "$tries"); do
    got=$(active_protocol_version)
    if [ "$got" = "$want" ]; then
      echo "$got"
      return 0
    fi
    sleep 3
  done
  echo "$got"
  return 1
}

if [ "$UPDATE_OP_FLOW_TEE" = true ]; then
  e2e_step "bootstrap 4-validator TEE localnet"
else
  e2e_step "bootstrap 4-validator non-TEE localnet"
fi
e2e_cleanup
e2e_bootstrap 4 || { e2e_summary; exit 1; }
e2e_start
if [ "$E2E_FAIL" -gt 0 ]; then
  e2e_summary
  exit 1
fi

e2e_step "wait for RPC and a few blocks"
PN=dn
for _ in $(seq 1 60); do
  PN=$(e2e_h 8545)
  if [ "$PN" != "dn" ] && [ "$PN" -ge 5 ] 2>/dev/null; then
    break
  fi
  sleep 3
done
[ "$PN" = "dn" ] || [ "$PN" -lt 5 ] 2>/dev/null && PN=$(e2e_fin 8545)
[ "$PN" = "dn" ] && PN=$(e2e_h 8545)
e2e_assert_ge "committee reached usable height" "$PN" 5

HEAD=$PN
ACTIVATION=$((HEAD + E2E_VOTE_WINDOW_BLOCKS + MIN_ACTIVATION_BUFFER + 30))
V0=$(e2e_v0key)
V1=$(e2e_vkey 1)
V2=$(e2e_vkey 2)
ACTIVE_VERSION="$(active_protocol_version)"
if [ -z "$ACTIVE_VERSION" ]; then
  e2e_log "could not read active protocol version from IUpdate.getActiveVersion"
  e2e_summary
  exit 1
fi
VERSION="$((ACTIVE_VERSION + 1))"
PAYLOAD="$(schedule_update_payload)"

e2e_step "propose update (validator-0, version $VERSION)"
PROPOSE_LOG=/tmp/e2e-update-propose.log
if ! run_update_propose "$V0" >"$PROPOSE_LOG" 2>&1; then
  e2e_log "propose failed:"
  tail -5 "$PROPOSE_LOG"
  e2e_assert "update propose transaction sent" false
else
  PROPOSE_TX=$(extract_tx_hash <"$PROPOSE_LOG")
  if [ -z "$PROPOSE_TX" ]; then
    e2e_log "propose output missing tx hash:"
    cat "$PROPOSE_LOG"
    e2e_assert "update propose transaction hash captured" false
  elif wait_tx_success "$PROPOSE_TX" "propose"; then
    e2e_assert "update propose transaction mined successfully" true
  else
    e2e_assert "update propose transaction mined successfully" false
  fi
fi

e2e_step "vote status after propose (pending)"
STATUS=""
for _ in $(seq 1 10); do
  STATUS=$("$E2E_CLI" --rpc-url "$RPC0" vote status --proposal-id 1 2>&1 || true)
  if echo "$STATUS" | grep -q 'Proposal #1:'; then
    break
  fi
  sleep 3
done
e2e_log "$STATUS"
e2e_assert "proposal #1 visible after propose" "$(echo "$STATUS" | grep -q 'Proposal #1:' && echo true || echo false)"
e2e_assert "proposal pending after propose" "$(echo "$STATUS" | grep -q 'status=pending' && echo true || echo false)"
e2e_assert "proposal targets update module" "$(echo "$STATUS" | grep -qi "target=$UPDATE_ADDR" && echo true || echo false)"
e2e_assert "proposal payload contains activation height" "$(echo "$STATUS" | grep -q "\"activationHeight\":$ACTIVATION" && echo true || echo false)"

e2e_step "cast yes votes from three validators"
for KEY in "$V0" "$V1" "$V2"; do
  VOTE_LOG=/tmp/e2e-update-vote.log
  if ! run_update_vote "$KEY" >"$VOTE_LOG" 2>&1; then
    e2e_log "vote failed for key ${KEY:0:10}..."
    tail -3 "$VOTE_LOG"
    e2e_assert "vote transaction sent" false
  else
    VOTE_TX=$(extract_tx_hash <"$VOTE_LOG")
    if [ -z "$VOTE_TX" ]; then
      e2e_assert "vote transaction hash captured (${KEY:0:10}...)" false
    elif wait_tx_success "$VOTE_TX" "vote"; then
      e2e_assert "vote transaction mined (${KEY:0:10}...)" true
    else
      e2e_assert "vote transaction mined (${KEY:0:10}...)" false
    fi
  fi
done

e2e_step "status after votes (still pending, yes tally visible)"
STATUS=$("$E2E_CLI" --rpc-url "$RPC0" vote status --proposal-id 1 2>&1 || true)
e2e_log "$STATUS"
e2e_assert "proposal still pending before deadline" "$(echo "$STATUS" | grep -q 'status=pending' && echo true || echo false)"
e2e_assert "three yes votes recorded" "$(echo "$STATUS" | grep -qE 'votes=3/0' && echo true || echo false)"
VOTE_DEADLINE=$(extract_deadline "$STATUS")
e2e_assert "vote deadline captured" "$([ -n "$VOTE_DEADLINE" ] && echo true || echo false)"
[ -z "$VOTE_DEADLINE" ] && VOTE_DEADLINE="$PN"

e2e_step "wait for vote approval and scheduled update"
PN=$(wait_height_gt "$VOTE_DEADLINE" 80)
e2e_assert_ge "committee passed vote deadline" "$PN" "$((VOTE_DEADLINE + 1))"
if wait_vote_status approved 60; then
  e2e_log "$STATUS"
  e2e_assert "proposal approved after deadline tally" true
else
  e2e_log "$STATUS"
  e2e_assert "proposal approved after deadline tally" false
fi
SCHEDULED_VERSION=$(scheduled_update_field 2)
SCHEDULED_ACTIVATION=$(scheduled_update_field 3)
SCHEDULED_STATUS=$(scheduled_update_field 5)
e2e_assert_eq "scheduled update version" "$VERSION" "$SCHEDULED_VERSION"
e2e_assert_eq "scheduled update activation height" "$ACTIVATION" "$SCHEDULED_ACTIVATION"
e2e_assert_eq "scheduled update waiting for activation" "0" "$SCHEDULED_STATUS"

e2e_step "wait for activation and active version readback"
PN=$(wait_height_gt "$ACTIVATION" 180)
e2e_assert_ge "committee passed activation height" "$PN" "$((ACTIVATION + 1))"
ACTIVE_AFTER=$(wait_active_version "$VERSION" 60)
e2e_assert_eq "active protocol version updated" "$VERSION" "$ACTIVE_AFTER"
SCHEDULED_STATUS=$(scheduled_update_field 5)
e2e_assert_eq "scheduled update marked activated" "1" "$SCHEDULED_STATUS"

e2e_step "state-root parity across committee nodes"
sleep 6
PN=$(e2e_fin 8545)
[ "$PN" = "dn" ] && PN=$(e2e_h 8545)
SR0=$(e2e_stateroot 8545 "$PN")
for PORT in 8546 8547 8548; do
  SR=$(e2e_stateroot "$PORT" "$PN")
  e2e_assert_eq "state_root parity @h$PN port $PORT" "$SR0" "$SR"
done

e2e_summary
