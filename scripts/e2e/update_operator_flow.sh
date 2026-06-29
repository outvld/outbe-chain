#!/usr/bin/env bash
# Operator smoke: propose and vote on an update via outbe-cli, assert status visibility,
# and check multi-node state-root parity. Uses the same gramine-mock TEE localnet
# harness as the S1–S7 e2e suite (sudo + Docker). Does not wait through the voting
# window or activation — those paths stay covered by in-memory Rust e2e tests.
#
# Env (optional):
#   E2E_REPO            repo root (default in lib.sh: /home/ubuntu/outbe-chain)
#   E2E_DIR / OUT_DIR    localnet data dir (default: fresh /tmp dir)
#   E2E_BIN             outbe-chain binary (default: target/debug/outbe-chain)
#   E2E_CLI             outbe-cli binary (default: target/debug/outbe-cli)
#   E2E_MOCK            outbe-tee-enclave-mock binary
#
# Requires: cast, jq, docker, sudo, foundry (cast)
set -uo pipefail

E2E_NAME=UPDATE_OP_FLOW
E2E_DIR="${OUT_DIR:-$(mktemp -d /tmp/outbe-update-op.XXXXXX)}"
export OUT_DIR="$E2E_DIR"
source "$(dirname "$0")/lib.sh"

MIN_ACTIVATION_BUFFER=100

binary_protocol_version() {
  local formatted
  formatted=$("$E2E_CLI" update status --rpc-url "$RPC0" 2>/dev/null \
    | sed -n 's/^Binary version: //p' | head -1)
  # CLI prints "v0.1 (1)"; propose expects "0.1" or raw u32.
  if [[ "$formatted" =~ ^v([0-9]+\.[0-9]+) ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$formatted" =~ \(([0-9]+)\)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo "$formatted"
}

run_update_propose() {
  "$E2E_CLI" update propose \
    --version "$VERSION" \
    --activation-height "$ACTIVATION" \
    --force \
    --private-key "$1" \
    --rpc-url "$RPC0"
}

run_update_vote() {
  "$E2E_CLI" update vote --proposal-id 1 --yes \
    --private-key "$1" \
    --rpc-url "$RPC0"
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
  sed -n 's/.*transaction sent: \(0x[0-9a-fA-F]\{64\}\).*/\1/p' | head -1
}

e2e_step "bootstrap 4-validator TEE localnet"
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
ACTIVATION=$((HEAD + MIN_ACTIVATION_BUFFER + 100000))
V0=$(e2e_v0key)
V1=$(e2e_vkey 1)
V2=$(e2e_vkey 2)
VERSION="$(binary_protocol_version)"
if [ -z "$VERSION" ]; then
  e2e_log "could not read binary protocol version from outbe-cli update status"
  e2e_summary
  exit 1
fi

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

e2e_step "status after propose (pending, not scheduled)"
STATUS=""
for _ in $(seq 1 10); do
  STATUS=$("$E2E_CLI" update status --proposal-id 1 --rpc-url "$RPC0" 2>&1 || true)
  if echo "$STATUS" | grep -q 'Proposal #1:'; then
    break
  fi
  sleep 3
done
e2e_log "$STATUS"
e2e_assert "proposal #1 visible after propose" "$(echo "$STATUS" | grep -q 'Proposal #1:' && echo true || echo false)"
e2e_assert "proposal pending after propose" "$(echo "$STATUS" | grep -q 'status=pending' && echo true || echo false)"
e2e_assert "no scheduled update before deadline tally" "$([ "$(echo "$STATUS" | grep -c 'Scheduled update')" -eq 0 ] && echo true || echo false)"

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
STATUS=$("$E2E_CLI" update status --proposal-id 1 --rpc-url "$RPC0" 2>&1 || true)
e2e_log "$STATUS"
e2e_assert "proposal still pending before deadline" "$(echo "$STATUS" | grep -q 'status=pending' && echo true || echo false)"
e2e_assert "three yes votes recorded" "$(echo "$STATUS" | grep -qE 'votes=3/' && echo true || echo false)"
e2e_assert "no scheduled update before deadline tally" "$([ "$(echo "$STATUS" | grep -c 'Scheduled update')" -eq 0 ] && echo true || echo false)"

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
