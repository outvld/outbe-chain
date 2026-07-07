#!/usr/bin/env bash
# Full follower e2e:
#   S1  cold --upstream follower syncs a RESHARED chain to lockstep
#   S1b follower-of-follower: follower2 --upstream=follower1 (tip publishing + serving)
#   S3  validator catch-up: kill validator-3 mid-epoch, restart, lockstep again
#   S2  warm promotion: stop follower1 -> provision keys/stake -> restart its DATADIR
#       as --validator -> confirm-ready -> reshare -> ACTIVE consensus participant
set -uo pipefail
cd "$(dirname "$0")/../.."
export PATH="$PATH:/home/ubuntu/.foundry/bin"
export TESTNET_EPOCH_LENGTH_BLOCKS=60 TESTNET_DKG_PREPARE_WINDOW_BLOCKS=15
export E2E_NAME=FOLLOWER
source scripts/e2e/lib.sh
BIN="$PWD/target/debug/outbe-chain"
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
# lockstep: head of port $1 within 4 blocks of committee (8545)
lockstep(){ local h c; h=$(e2e_h "$1"); c=$(e2e_h 8545); [ "$h" != "dn" ] && [ "$c" != "dn" ] && [ $((c - h)) -le 4 ] 2>/dev/null; }
wait_lockstep(){ local port="$1" tries="${2:-30}" i; for i in $(seq 1 "$tries"); do sleep 6; lockstep "$port" && return 0; done; return 1; }

launch_follower(){ # $1=dir $2=http $3=p2p $4=disc5 $5=auth $6=upstream_port (all CANONICAL slot-0 ports; offset applied here)
  local fd="$1"; mkdir -p "$fd/data" "$fd/logs"
  # On a TEE chain a full-execution follower re-runs offer + registerEnclave txs
  # through the enclave (both land in the receipts root), so it needs an enclave
  # holding the (lifetime-constant) offer key — the node's startup guardrail
  # enforces this. Here we share validator-0's enclave (:7000, mock, thread-per-
  # connection) which already holds the offer key; a real follower gets its own
  # via `outbe-cli tee join` before sync.
  RUST_MIN_STACK=16777216 RUST_LOG="info,outbe_consensus::follow=debug" \
  setsid nohup env "PATH=$PATH" "$BIN" node \
    --chain "$E2E_DIR/genesis.json" --datadir "$fd/data" \
    --http --http.addr 0.0.0.0 --http.port "$(e2e_port "$2")" --http.api eth,net,web3,outbe \
    --port "$(e2e_port "$3")" --discovery.port "$(e2e_port "$3")" --discovery.v5.addr 127.0.0.1 --discovery.v5.port "$(e2e_port "$4")" \
    --p2p-secret-key-hex "$(openssl rand -hex 32)" --authrpc.port "$(e2e_port "$5")" \
    --ipcpath "$fd/data/reth.ipc" --log.file.directory "$fd/logs" \
    --tee-enclave-socket "127.0.0.1:$(e2e_port 7000)" \
    --upstream "$(e2e_url "$6")" >> "$fd/node.log" 2>&1 < /dev/null &
  echo "  follower @$1 pid $!"
}

echo "===== bootstrap + start 4-validator committee (epoch=60) ====="
e2e_cleanup
rm -rf "$E2E_DIR/follower" "$E2E_DIR/follower2" 2>/dev/null
e2e_bootstrap 4 || { echo BOOTSTRAP_FAIL; exit 1; }
e2e_start

echo "===== drive PAST a reshare ====="
VER=0
for _ in $(seq 1 70); do
  sleep 5
  VER=$(cast rpc outbe_consensusStatus --rpc-url "$RPC0" 2>/dev/null | jq -r '.vrfMaterialVersion // 0')
  [ "$VER" != "0" ] && [ "$VER" != "null" ] && break
done
[ "$VER" = "0" ] || [ "$VER" = "null" ] && { echo "NO RESHARE"; exit 2; }
echo "reshared: version=$VER h=$(e2e_h 8545)"

echo "===== S1: cold follower1 (--upstream committee) syncs past the reshare ====="
launch_follower "$E2E_DIR/follower" 8559 30317 31317 8565 8545
if wait_lockstep 8559 30; then ok "S1 follower1 lockstep (head=$(e2e_h 8559) vs committee=$(e2e_h 8545))"; else bad "S1 follower1 stuck (head=$(e2e_h 8559) vs $(e2e_h 8545))"; fi

echo "===== S1b: follower2 --upstream=FOLLOWER1 (tip publish + getFinalization serving) ====="
F1TIP=$(cast rpc outbe_consensusStatus --rpc-url "$(e2e_url 8559)" 2>/dev/null | jq -r '.lastFinalizedBlock // 0')
echo "  follower1 published tip: $F1TIP"
if [ "${F1TIP:-0}" -gt 0 ] 2>/dev/null; then ok "S1b follower1 publishes lastFinalizedBlock=$F1TIP"; else bad "S1b follower1 tip not published ($F1TIP)"; fi
launch_follower "$E2E_DIR/follower2" 8560 30318 31318 8566 8559
if wait_lockstep 8560 30; then ok "S1b follower2 (chained off follower1) lockstep (head=$(e2e_h 8560))"; else bad "S1b follower2 stuck (head=$(e2e_h 8560) vs $(e2e_h 8545))"; fi

echo "===== S3: validator-3 catch-up (kill mid-epoch, restart, relockstep) ====="
# wait for an early-epoch position so the downtime stays inside one epoch
for _ in $(seq 1 40); do H=$(e2e_h 8545); P=$(( (H-1) % 60 )); [ "$P" -ge 3 ] && [ "$P" -le 28 ] && break; sleep 4; done
echo "  killing validator-3 at h=$(e2e_h 8545) (epoch pos $P)"
e2e_kill_validator 3
sleep 25
H_DOWN=$(e2e_h 8548 2>/dev/null || echo dn)
echo "  restarting validator-3 (was at ~$H_DOWN, committee $(e2e_h 8545))"
BOOTNODES=$(paste -sd, "$E2E_DIR/reth-bootnodes.txt")
V3SECRET=$(tr -d '[:space:]' < "$E2E_DIR/validator-3/reth-p2p-secret.hex")
# Canonical validator-3 ports (30303/8545/... + 3) shifted by this instance's
# offset via e2e_port, which the current shell expands before sudo runs.
sudo env RUST_MIN_STACK=16777216 bash -c "setsid nohup '$BIN' node --validator \
  --chain '$E2E_DIR/genesis.json' --datadir '$E2E_DIR/validator-3/data' \
  --http --http.addr 0.0.0.0 --http.port $(e2e_port 8548) --http.api eth,net,web3,outbe \
  --port $(e2e_port 30306) --discovery.port $(e2e_port 30306) --discovery.v5.addr 127.0.0.1 --discovery.v5.port $(e2e_port 31306) \
  --bootnodes '$BOOTNODES' --p2p-secret-key-hex '$V3SECRET' \
  --authrpc.port $(e2e_port 8554) --ipcpath '$E2E_DIR/validator-3/data/reth.ipc' --metrics 0.0.0.0:$(e2e_port 9104) \
  --log.file.directory '$E2E_DIR/validator-3/logs' \
  --consensus.signing-key '$E2E_DIR/validator-3/signing-key.hex' \
  --validator.evm-key '$E2E_DIR/validator-3/evm-key.hex' \
  --consensus.listen-addr 127.0.0.1:$(e2e_port 30403) --consensus.use-local-defaults \
  --tee-enclave-socket 127.0.0.1:$(e2e_port 7003) \
  >> '$E2E_DIR/validator-3/node.log' 2>&1 < /dev/null &"
if wait_lockstep 8548 30; then ok "S3 validator-3 caught up (head=$(e2e_h 8548) vs $(e2e_h 8545))"; else bad "S3 validator-3 did not catch up (head=$(e2e_h 8548) vs $(e2e_h 8545))"; fi

echo "===== S2: WARM promotion — follower1 datadir restarts as a validator ====="
# stop followers (follower1's datadir becomes the promoted validator's)
for pid in $(ps -eo pid,args | grep "outbe-chain node" | grep -E "$E2E_DIR/follower2?/data" | grep -v grep | awk '{print $1}'); do kill -9 "$pid" 2>/dev/null; done
sleep 3
F_STOP_H=$(e2e_h 8559 2>/dev/null || echo dn)
echo "  follower1 stopped (synced to ~cached height); provisioning v5 keys/registration"
e2e_provision_joiner
echo "  moving follower1 datadir -> validator-4/data (warm state)"
mv "$E2E_DIR/follower/data" "$E2E_DIR/validator-4/data"
e2e_stake "$V5_KEY" 1000
echo "  launching v5 (--validator, warm datadir) at committee h=$(e2e_h 8545)"
e2e_launch_joiner
if wait_lockstep 8549 30; then ok "S2 v5 warm restart synced (head=$(e2e_h 8549))"; else bad "S2 v5 did not sync after warm restart (head=$(e2e_h 8549))"; fi
e2e_confirm_ready "$V5_KEY"
echo "  confirm-ready sent at h=$(e2e_h 8545); waiting for the reshare to activate v5..."
ACT=false
for _ in $(seq 1 60); do
  sleep 6
  [ "$(e2e_participant "$V5_ADDR")" = "true" ] && { ACT=true; break; }
done
if $ACT; then ok "S2 v5 is a consensus participant (count=$(e2e_consensus_count))"; else bad "S2 v5 never became a consensus participant"; fi
# post-activation: v5 must keep advancing in lockstep (no false-positive ACTIVE)
sleep 20
if lockstep 8549; then ok "S2 post-activation lockstep (head=$(e2e_h 8549) vs $(e2e_h 8545))"; else bad "S2 v5 stalled after activation (head=$(e2e_h 8549) vs $(e2e_h 8545))"; fi

echo "===== SUMMARY: PASS=$PASS FAIL=$FAIL ====="
[ "$FAIL" -eq 0 ] && echo "E2E_ALL_GREEN" || echo "E2E_HAS_FAILURES"
echo "E2E_FINISHED"
