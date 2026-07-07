#!/usr/bin/env bash
# Shared harness for the e2e.md scenario suite (S1-S7).
#
# These are SHELL e2e tests against a gramine-mock TEE localnet (no real SGX/DCAP).
# Assertions are adapted to the ACTUAL protocol behavior; where e2e.md's spec
# diverges from the implementation, scripts/e2e/README.md documents why.
#
# Source this from a scenario script:  source "$(dirname "$0")/lib.sh"
# Then call:  e2e_cleanup; e2e_bootstrap <N>; e2e_start; ...; e2e_summary
#
# Conventions:
#  - committee validators i=0..N-1 on http 8545+i, p2p 30400+i, consensus 30400+i,
#    tee 7000+i. A joiner is index N (v5 for a 4-node committee): http 8549, etc.
#  - every PASS/FAIL goes through e2e_assert/e2e_assert_eq so e2e_summary can tally.
set -uo pipefail

# ---- paths / constants -------------------------------------------------------
E2E_REPO="${E2E_REPO:-/home/ubuntu/outbe-chain}"
cd "$E2E_REPO"
export PATH="$PATH:/home/ubuntu/.foundry/bin"

# ---- instance isolation (concurrent suites on one host) ----------------------
# E2E_SLOT picks an isolated instance: its own port band, data dir, docker
# containers and log files, so several suites can run on one machine without
# colliding. Everything derives from ONE knob:
#   E2E_PORT_OFFSET = E2E_SLOT * 200   (added to every base port)
#   E2E_TAG         = "" for slot 0, "sN" otherwise (suffixes dir/containers/logs)
# Slot 0 (the default) is byte-identical to the historical scheme, so CI is
# unchanged. Stride 200 keeps the cramped port bands (reth-p2p 30303, consensus
# 30400, discv5 31303) collision-free for slots 0..4 — five concurrent suites.
# Port args passed to the RPC readers below (e.g. `e2e_h 8545`) are always the
# CANONICAL slot-0 numbers; e2e_port()/e2e_url() add the offset in ONE place, so
# call sites stay readable and slot 0 is a no-op. Chain id stays 54322345 for
# every slot (runtime logic branches on it); isolation is by port/dir alone.
E2E_SLOT="${E2E_SLOT:-0}"
E2E_PORT_STRIDE="${E2E_PORT_STRIDE:-200}"
E2E_PORT_OFFSET="${E2E_PORT_OFFSET:-$((E2E_SLOT * E2E_PORT_STRIDE))}"
if [ "${E2E_SLOT}" -eq 0 ] 2>/dev/null; then E2E_TAG="${E2E_TAG:-}"; else E2E_TAG="${E2E_TAG:-s$E2E_SLOT}"; fi
export E2E_SLOT E2E_PORT_OFFSET E2E_TAG
# canonical slot-0 port -> this instance's real port / url
e2e_port(){ echo "$(( $1 + E2E_PORT_OFFSET ))"; }
e2e_url(){ echo "http://localhost:$(( $1 + E2E_PORT_OFFSET ))"; }

E2E_DIR="${E2E_DIR:-/tmp/e2e-suite${E2E_TAG:+-$E2E_TAG}}"
E2E_BIN="${E2E_BIN:-$E2E_REPO/target/debug/outbe-chain}"
E2E_MOCK="${E2E_MOCK:-$E2E_REPO/target/release/outbe-tee-enclave-mock}"
E2E_CLI="${E2E_CLI:-$E2E_REPO/target/debug/outbe-cli}"
E2E_KEYGEN="${E2E_KEYGEN:-$E2E_REPO/target/debug/outbe-keygen}"
E2E_SEED="${E2E_SEED:-$E2E_REPO/scripts/seed-testnet-lowstake.json}"
RPC0="$(e2e_url 8545)"
# per-instance log files (slot 0 keeps the historical /tmp/e2e-*.log names)
E2E_LOG_PREFIX="${E2E_LOG_PREFIX:-/tmp/e2e${E2E_TAG:+-$E2E_TAG}}"
E2E_BOOT_LOG="${E2E_BOOT_LOG:-${E2E_LOG_PREFIX}-boot.log}"
E2E_START_LOG="${E2E_START_LOG:-${E2E_LOG_PREFIX}-start.log}"

# Active worldwide-day = the chain's current date, matching how bootstrap-testnet.sh
# seeds it: WorldwideDay::from_timestamp = date_key(genesis_ts + UTC_PLUS_14_OFFSET).
# The net boots "today", so offers/queries must target today — not a fixed calendar
# day (a stale day is not OFFERING and wedges metadosis; see bootstrap-testnet.sh).
E2E_WWD="${E2E_WWD:-$(date -u -d "@$(( $(date +%s) + 50400 ))" +%Y%m%d 2>/dev/null \
    || date -u -r "$(( $(date +%s) + 50400 ))" +%Y%m%d)}"

# Protocol addresses (README "EVM").
TEE_ADDR=0x000000000000000000000000000000000000EE0A
TRIBUTE_ADDR=0x0000000000000000000000000000000000001101
VS_ADDR=0x000000000000000000000000000000000000EE00
STK_ADDR=0x000000000000000000000000000000000000EE02
GAS="--gas-price 1000000000"

# ---- tally -------------------------------------------------------------------
E2E_PASS=0
E2E_FAIL=0
E2E_NAME="${E2E_NAME:-scenario}"

e2e_log()  { echo "[$E2E_NAME] $*"; }
e2e_step() { echo; echo "### [$E2E_NAME] $*"; }

e2e_assert() { # cond_desc  actual_bool(true/false-ish)
  local desc="$1" cond="$2"
  if [ "$cond" = "true" ] || [ "$cond" = "1" ] || [ "$cond" = "PASS" ]; then
    E2E_PASS=$((E2E_PASS+1)); echo "  PASS: $desc"
  else
    E2E_FAIL=$((E2E_FAIL+1)); echo "  FAIL: $desc (got '$cond')"
  fi
}
e2e_assert_eq() { # desc expected actual
  local desc="$1" exp="$2" act="$3"
  if [ "$exp" = "$act" ]; then
    E2E_PASS=$((E2E_PASS+1)); echo "  PASS: $desc (==$exp)"
  else
    E2E_FAIL=$((E2E_FAIL+1)); echo "  FAIL: $desc (expected '$exp' got '$act')"
  fi
}
e2e_assert_ge() { # desc actual min
  local desc="$1" act="$2" min="$3"
  if [ "$act" != "dn" ] && [ "$act" -ge "$min" ] 2>/dev/null; then
    E2E_PASS=$((E2E_PASS+1)); echo "  PASS: $desc ($act >= $min)"
  else
    E2E_FAIL=$((E2E_FAIL+1)); echo "  FAIL: $desc (got '$act', want >= $min)"
  fi
}
e2e_summary() {
  echo
  echo "### [$E2E_NAME] RESULT: $E2E_PASS passed, $E2E_FAIL failed"
  [ "$E2E_FAIL" -eq 0 ] && echo "[$E2E_NAME] SCENARIO_PASS" || echo "[$E2E_NAME] SCENARIO_FAIL"
  return "$E2E_FAIL"
}

# ---- RPC readers -------------------------------------------------------------
e2e_h()  { cast block-number --rpc-url "$(e2e_url "$1")" 2>/dev/null || echo dn; }      # head
# finalized block number as DECIMAL (jq gives 0x-hex; convert so `cast block <N>` works).
e2e_fin(){ local n; n=$(cast block finalized --rpc-url "$(e2e_url "$1")" --json 2>/dev/null | jq -r '.number//"dn"' 2>/dev/null); [ "$n" = "dn" ] || [ -z "$n" ] && { echo dn; return; }; printf '%d\n' "$n" 2>/dev/null || echo dn; }
e2e_supply(){ cast call $TRIBUTE_ADDR 'totalSupply()(uint256)' --rpc-url "$(e2e_url "$1")" 2>/dev/null || echo dn; }
e2e_active(){ cast call $VS_ADDR 'activeValidatorCount()(uint32)' --rpc-url "${2:-$RPC0}" 2>/dev/null || echo dn; }
# consensus participants = ACTIVE + EXITING-with-share (stays until the exclusion reshare).
e2e_consensus_count(){ cast call $VS_ADDR 'activeConsensusCount()(uint32)' --rpc-url "${2:-$RPC0}" 2>/dev/null || echo dn; }
e2e_participant(){ cast call $VS_ADDR 'isConsensusParticipant(address)(bool)' "$1" --rpc-url "${2:-$RPC0}" 2>/dev/null || echo dn; }
e2e_bootstrapped(){ cast call $TEE_ADDR 'isBootstrapped()(bool)' --rpc-url "${1:-$RPC0}" 2>/dev/null; }
e2e_stateroot(){ cast block "$2" --rpc-url "$(e2e_url "$1")" --json 2>/dev/null | jq -r '.stateRoot//"dn"' 2>/dev/null || echo dn; }
e2e_blockhash(){ cast block "$2" --rpc-url "$(e2e_url "$1")" --json 2>/dev/null | jq -r '.hash//"dn"' 2>/dev/null || echo dn; }
# validator status code (0 REGISTERED,1 PENDING,2 ACTIVE,3 EXITING,4 UNBONDING,5 INACTIVE)
e2e_status(){ cast call $VS_ADDR 'validatorByAddress(address)(address,bytes,uint256,uint8,uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)' "$1" --rpc-url "${2:-$RPC0}" 2>/dev/null | sed -n '4p' || echo dn; }
e2e_hasshare(){ cast call $VS_ADDR 'validatorByAddress(address)(address,bytes,uint256,uint8,uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)' "$1" --rpc-url "${2:-$RPC0}" 2>/dev/null | sed -n '12p' || echo dn; }
e2e_missedvotes(){ cast call $VS_ADDR 'validatorByAddress(address)(address,bytes,uint256,uint8,uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)' "$1" --rpc-url "${2:-$RPC0}" 2>/dev/null | sed -n '7p' || echo dn; }
# validatorByAddress field lines: 1 addr, 2 pubkey, 3 stake, 4 status, 5 slashCount,
# 6 missedBlocks, 7 missedVotes, 8 blocksProposed, 9 joined, 10 deactivated, 11 unbondEnd, 12 hasShare
e2e_stake_amount(){ cast call $VS_ADDR 'validatorByAddress(address)(address,bytes,uint256,uint8,uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)' "$1" --rpc-url "${2:-$RPC0}" 2>/dev/null | sed -n '3p' | awk '{print $1}' || echo dn; }
e2e_slashcount(){ cast call $VS_ADDR 'validatorByAddress(address)(address,bytes,uint256,uint8,uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)' "$1" --rpc-url "${2:-$RPC0}" 2>/dev/null | sed -n '5p' || echo dn; }

# wait until http port $1 head >= $2 (timeout $3 polls * 6s)
e2e_wait_height(){ local port="$1" want="$2" tries="${3:-30}"; local hh; for _ in $(seq 1 "$tries"); do sleep 6; hh=$(e2e_h "$port"); { [ "$hh" != "dn" ] && [ "$hh" -ge "$want" ] 2>/dev/null; } && { echo "$hh"; return 0; }; done; echo "$hh"; return 1; }

# ---- lifecycle ---------------------------------------------------------------
# This instance's docker enclave container name for validator/joiner index $1.
# Slot 0 keeps the historical `outbe-tee-gramine-<i>`; other slots get a tag so
# a concurrent suite's cleanup never touches this instance's containers.
e2e_ctr(){ echo "outbe-tee-gramine${E2E_TAG:+-$E2E_TAG}-$1"; }
e2e_cleanup(){
  sudo env PATH="$PATH" ./scripts/run-testnet.sh stop "$E2E_DIR" >/dev/null 2>&1
  # Committee validators run under run-supervised.sh, which RESPAWNS a killed node
  # child. So kill the SUPERVISORS first (else the node comes back), then any
  # remaining node processes (the directly-launched joiner is not supervised), all
  # by explicit pid with sudo (run-testnet starts them root-owned; pkill -f is
  # unreliable for these). This also clears orphans a prior scenario left behind
  # (e.g. a validator it killed mid-test that run-testnet's stop no longer tracks).
  # SCOPED to $E2E_DIR (every node/supervisor cmdline carries its --datadir /
  # exit-file path) so a concurrent suite on another slot is left untouched.
  sudo pkill -9 -f "run-supervised.sh $E2E_DIR/" 2>/dev/null
  sleep 1
  for pid in $(ps -eo pid,args | grep "outbe-chain node" | grep "$E2E_DIR/" | grep -v "run-supervised" | grep -v grep | awk '{print $1}'); do sudo kill -9 "$pid" 2>/dev/null; done
  # Remove this instance's enclave containers (committee 0..N + joiner). Named
  # explicitly (not a fuzzy "outbe-tee" substring filter) so slot 0's cleanup
  # can't remove slot 1's `...-s1-*` containers and vice-versa.
  for c in $(seq 0 9); do sudo docker rm -f "$(e2e_ctr "$c")" >/dev/null 2>&1; done
  sudo rm -rf "$E2E_DIR"
  sleep 3
}

# e2e_bootstrap <N>  (default 4). Honors env overrides forwarded to bootstrap-testnet.sh.
# E2E_PORT_OFFSET is exported, so bootstrap-testnet.sh offsets validators.json /
# reth-bootnodes.txt ports to match this instance.
e2e_bootstrap(){
  local n="${1:-4}"
  OUTBE_CHAIN_BINARY="$E2E_BIN" ./scripts/bootstrap-testnet.sh "$n" "$E2E_DIR" "$E2E_SEED" >"$E2E_BOOT_LOG" 2>&1 \
    || { echo "[$E2E_NAME] BOOTSTRAP_FAIL"; tail -5 "$E2E_BOOT_LOG"; return 1; }
}

# e2e_start  — start the committee with the gramine mock enclave, wait for bootstrap.
# `sudo env` passes ONLY the vars listed, so E2E_PORT_OFFSET/E2E_TAG must be
# forwarded explicitly for run-testnet.sh to bind this instance's ports/containers.
e2e_start(){
  sudo env OUTBE_TEE_ENCLAVE=1 OUTBE_TEE_ENCLAVE_MOCK=1 OUTBE_TEE_SEAL=1 \
    OUTBE_TEE_ENCLAVE_BINARY="$E2E_MOCK" OUTBE_CHAIN_BINARY="$E2E_BIN" PATH="$PATH" \
    E2E_PORT_OFFSET="$E2E_PORT_OFFSET" E2E_TAG="$E2E_TAG" \
    ./scripts/run-testnet.sh start "$E2E_DIR" >"$E2E_START_LOG" 2>&1
  local ok=false
  for _ in $(seq 1 18); do sleep 5; [ "$(e2e_bootstrapped)" = "true" ] && { ok=true; break; }; done
  e2e_assert "TEE chain bootstrapped" "$([ "$ok" = true ] && echo true || echo false)"
}

e2e_v0key(){ echo "0x$(tr -d '[:space:]' < "$E2E_DIR/validator-0/evm-key.hex")"; }
e2e_vkey(){ echo "0x$(tr -d '[:space:]' < "$E2E_DIR/validator-$1/evm-key.hex")"; }

# submit a tribute offer for the genesis OFFERING day with creator key $1; retry until supply rises to $2
e2e_offer(){ local key="$1" want="$2" try; for try in 1 2 3 4 5; do "$E2E_CLI" tribute offer "$E2E_WWD" --amount 100 --currency 840 --private-key "$key" --rpc-url "$RPC0" >/dev/null 2>&1; sleep 5; [ "$(e2e_supply 8545)" = "$want" ] && return 0; done; return 1; }

# ---- joiner (v5) management --------------------------------------------------
# Provision joiner index 4 (v5): keys, fund, register, p2p, enclave, tee join.
# Sets globals V5_KEY V5_ADDR V5_BLS. Does NOT stake (caller decides).
e2e_provision_joiner(){
  local vd="$E2E_DIR/validator-4"; mkdir -p "$vd"
  "$E2E_KEYGEN" hybrid --output-dir "$vd" >/dev/null 2>&1
  V5_BLS=$("$E2E_KEYGEN" show-pubkey --key "$vd/signing-key.hex" 2>/dev/null | grep -oE "[0-9a-f]{96}" | head -1)
  V5_KEY="0x$(tr -d '[:space:]' < "$vd/evm-key.hex")"
  V5_ADDR=$(cast wallet address --private-key "$V5_KEY")
  local sig; sig=$("$E2E_KEYGEN" sign-registration --key "$vd/signing-key.hex" --validator-address "$V5_ADDR" 2>/dev/null | grep -oE "[0-9a-f]{120,}" | head -1)
  python3 -c "import secrets;print(secrets.token_hex(32))" > "$vd/reth-p2p-secret.hex"
  local v0; v0=$(e2e_v0key)
  cast send "$V5_ADDR" --value 2000ether --private-key "$v0" --rpc-url "$RPC0" $GAS >/dev/null 2>&1
  cast send $VS_ADDR "registerValidator(address,bytes,bytes)" "$V5_ADDR" "0x$V5_BLS" "0x$sig" --private-key "$V5_KEY" --rpc-url "$RPC0" $GAS >/dev/null 2>&1
  # On-chain consensus P2P address = 00 04 <127.0.0.1> <port>. Port is the joiner's
  # consensus port (canonical 30404) shifted by this instance's offset so committee
  # peers dial the right socket. 0x00047f000001 + 2-byte port (0x76c4 == 30404).
  local p2p_bytes; p2p_bytes=$(printf '0x00047f000001%04x' "$(e2e_port 30404)")
  cast send $VS_ADDR "setP2pAddress(address,uint8,bytes)" "$V5_ADDR" 1 "$p2p_bytes" --private-key "$V5_KEY" --rpc-url "$RPC0" $GAS >/dev/null 2>&1
  local jctr jtee; jctr=$(e2e_ctr 4); jtee="127.0.0.1:$(e2e_port 7004)"
  sudo docker rm -f "$jctr" >/dev/null 2>&1
  sudo docker run -d --name "$jctr" --security-opt seccomp=unconfined --network host \
    -v "$E2E_MOCK:/app/outbe-tee-enclave:ro" outbe-tee-enclave-gramine --socket "$jtee" --dkg-seed 5 >/dev/null 2>&1
  local _; for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$(e2e_port 7004)") 2>/dev/null && { exec 3>&-; break; }; sleep 0.1; done
  "$E2E_CLI" tee join --enclave-socket "$jtee" --rpc-url "$RPC0" --private-key "$V5_KEY" --timeout-secs 60 2>&1 | grep -E "installed|Error" | head -1
}

# launch the joiner node (validator mode, verifier-join args). Honors $V5_EXTRA_ARGS.
e2e_launch_joiner(){
  local vd="$E2E_DIR/validator-4"; mkdir -p "$vd/data" "$vd/logs"
  local bootnodes peers secret
  bootnodes=$(paste -sd, "$E2E_DIR/reth-bootnodes.txt")
  peers=$(python3 -c "import json;print(','.join(f\"{v['public_key']}@{v['p2p_address']}\" for v in json.load(open('$E2E_DIR/validators.json'))))")
  secret=$(tr -d '[:space:]' < "$vd/reth-p2p-secret.hex")
  RUST_MIN_STACK=16777216 nohup "$E2E_BIN" node --validator --chain "$E2E_DIR/genesis.json" --datadir "$vd/data" \
    --http --http.addr 0.0.0.0 --http.port "$(e2e_port 8549)" --http.api eth,net,web3,outbe --port "$(e2e_port 30307)" --discovery.port "$(e2e_port 30307)" \
    --discovery.v5.addr 127.0.0.1 --discovery.v5.port "$(e2e_port 31307)" --bootnodes "$bootnodes" --p2p-secret-key-hex "$secret" \
    --authrpc.port "$(e2e_port 8555)" --ipcpath "$vd/data/reth.ipc" --metrics "0.0.0.0:$(e2e_port 9105)" --log.file.directory "$vd/logs" \
    --consensus.signing-key "$vd/signing-key.hex" --validator.evm-key "$vd/evm-key.hex" \
    --consensus.listen-addr "127.0.0.1:$(e2e_port 30404)" --consensus.peers "$peers" --consensus.use-local-defaults \
    --tee-enclave-socket "127.0.0.1:$(e2e_port 7004)" \
    --consensus.public-polynomial "$E2E_DIR/polynomial.hex" --consensus.dkg-output "$E2E_DIR/dkg-output.hex" \
    ${V5_EXTRA_ARGS:-} >> "$vd/node.log" 2>&1 &
  echo $! > "$vd/node.pid"
}
e2e_stop_joiner(){ [ -f "$E2E_DIR/validator-4/node.pid" ] && kill -9 "$(cat "$E2E_DIR/validator-4/node.pid")" 2>/dev/null; sleep 3; }
e2e_joiner_log_has(){ grep -q "$1" "$E2E_DIR/validator-4/node.log" 2>/dev/null && echo true || echo false; }
# grep -c prints "0" AND exits 1 on no-match, so `|| echo 0` would emit a SECOND
# "0" and corrupt integer comparisons — capture the count instead.
e2e_joiner_log_count(){ local n; n=$(grep -c "$1" "$E2E_DIR/validator-4/node.log" 2>/dev/null); echo "${n:-0}"; }

# stake $2 ether from joiner $1 key (default V5_KEY); joiner goes REGISTERED->PENDING.
e2e_stake(){ local key="${1:-$V5_KEY}" amt="${2:-1000}"; cast send $STK_ADDR "stake(address,uint256)" "$(cast wallet address --private-key "$key")" "${amt}ether" --value "${amt}ether" --private-key "$key" --rpc-url "$RPC0" $GAS >/dev/null 2>&1; }
# confirm a PENDING joiner is synced/ready (stale-join guard) — key $1 (default V5_KEY).
e2e_confirm_ready(){ local key="${1:-$V5_KEY}"; "$E2E_CLI" validator confirm-ready --private-key "$key" --rpc-url "$RPC0" 2>&1 | grep -iE "sent|error" | head -1; }
# deactivate validator with key $1 (self-deactivate).
e2e_deactivate(){ local key="${1:-$V5_KEY}"; cast send $VS_ADDR "deactivateValidator(address)" "$(cast wallet address --private-key "$key")" --private-key "$key" --rpc-url "$RPC0" $GAS >/dev/null 2>&1; }

# kill a committee validator i (0..N-1) so it STAYS down; container/enclave untouched.
# run-supervised.sh does not respawn (runs once, exits when the child exits), but a
# -9 on the supervisor orphans a still-running node child, so target the node by its
# datadir and kill both the node and its supervisor.
e2e_kill_validator(){
  local i="$1"
  # Match the full "$E2E_DIR/validator-$i/data" path so a concurrent suite's
  # validator-$i (same relative path, different slot dir) is never killed.
  for pid in $(ps -eo pid,args | grep "outbe-chain node" | grep "$E2E_DIR/validator-$i/data" | grep -v grep | awk '{print $1}'); do sudo kill -9 "$pid" 2>/dev/null; done
  for pid in $(ps -eo pid,args | grep "run-supervised" | grep "$E2E_DIR/validator-$i/data" | grep -v grep | awk '{print $1}'); do sudo kill -9 "$pid" 2>/dev/null; done
}
# committee validator log probe (node.log). See e2e_joiner_log_count re grep -c.
e2e_val_log_count(){ local n; n=$(grep -c "$2" "$E2E_DIR/validator-$1/node.log" 2>/dev/null); echo "${n:-0}"; }
