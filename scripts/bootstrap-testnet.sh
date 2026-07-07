#!/usr/bin/env bash
# Bootstrap and optionally run a local testnet with N validators.
#
# Usage:
#   ./scripts/bootstrap-testnet.sh <NUM_VALIDATORS> <OUTPUT_DIR> [SEED_FILE]
#
# Example:
#   ./scripts/bootstrap-testnet.sh 4 /tmp/outbe-testnet
#   ./scripts/bootstrap-testnet.sh 4 /tmp/outbe-testnet scripts/seed-testnet.json
#
# This script:
#   1. Runs DKG bootstrap to generate threshold keys + individual signing keys + polynomial + validators.json
#   2. Generates genesis.json (chain ID 54322345, pre-funds validators)
#   2b. (Optional) Seeds genesis with precompile storage from SEED_FILE
#   3. Prints startup commands for each validator

set -euo pipefail

NUM_VALIDATORS="${1:?Usage: $0 <num_validators> <output_dir> [seed_file]}"
OUTPUT_DIR="${2:?Usage: $0 <num_validators> <output_dir> [seed_file]}"
OUTBE_CONSENSUS_HOST_PATTERN="${OUTBE_CONSENSUS_HOST_PATTERN:-127.0.0.1}"
# Uniform port shift so multiple localnets can run in parallel. It is baked into
# the consensus p2p addresses (validators.json → genesis) and the reth bootnodes
# below; run-testnet.sh must launch with the SAME PORT_OFFSET.
PORT_OFFSET="${PORT_OFFSET:-0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEED_ARG="${3:-$SCRIPT_DIR/seed-testnet.json}"
if [ "$SEED_ARG" = "none" ]; then
    SEED_FILE=""
else
    SEED_FILE="$SEED_ARG"
fi

# Honor env overrides (e.g. a longer epoch to keep DKG reshare rounds from
# overlapping in tests); fall back to the localnet defaults when unset.
: "${TESTNET_EPOCH_LENGTH_BLOCKS:=120}"
: "${TESTNET_DKG_PREPARE_WINDOW_BLOCKS:=30}"
: "${TESTNET_DKG_ACTIVATION_GRACE_BLOCKS:=30}"

# Locate binary. OUTBE_CHAIN_BINARY is the explicit override used by CI,
# release smoke tests, and local operators who want release binaries.
if [ -n "${OUTBE_CHAIN_BINARY:-}" ]; then
    if [ ! -x "$OUTBE_CHAIN_BINARY" ]; then
        echo "Error: OUTBE_CHAIN_BINARY is set but not executable: $OUTBE_CHAIN_BINARY"
        exit 1
    fi
else
    OUTBE_CHAIN_BINARY=""
    for candidate in ./target/debug/outbe-chain ./target/release/outbe-chain; do
        if [ -x "$candidate" ]; then
            OUTBE_CHAIN_BINARY="$candidate"
            break
        fi
    done
    if [ -z "$OUTBE_CHAIN_BINARY" ]; then
        echo "Error: outbe-chain binary not found. Run 'cargo build --bin outbe-chain' or set OUTBE_CHAIN_BINARY."
        exit 1
    fi
fi

echo "Using outbe-chain binary: $OUTBE_CHAIN_BINARY"

echo "=== Outbe Testnet Bootstrap ==="
echo "Validators: $NUM_VALIDATORS"
echo "Output:     $OUTPUT_DIR"
echo "Epoch:      ${TESTNET_EPOCH_LENGTH_BLOCKS} blocks"
echo "DKG:        every ${TESTNET_EPOCH_LENGTH_BLOCKS} blocks, prepare ${TESTNET_DKG_PREPARE_WINDOW_BLOCKS} blocks before activation"
echo

# Bootstrap must start from a clean directory. Reusing a previous datadir with a
# new genesis/validator set leaves stale chain DB, PID files, IPC paths, and lock
# files behind, which makes localnet smoke results meaningless.
if [ -d "$OUTPUT_DIR" ]; then
    PID_DIR="$OUTPUT_DIR/pids"
    if [ -d "$PID_DIR" ]; then
        for pid_file in "$PID_DIR"/validator-*.pid; do
            [ -f "$pid_file" ] || continue
            pid="$(cat "$pid_file" 2>/dev/null || true)"
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                echo "Error: validator process $pid from $pid_file is still running."
                echo "Run './scripts/run-testnet.sh stop $OUTPUT_DIR' before bootstrapping."
                exit 1
            fi
        done
    fi
    rm -rf "$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR"

# Step 1: DKG bootstrap
echo "--- Step 1: DKG Bootstrap ---"
"$OUTBE_CHAIN_BINARY" dkg bootstrap --output-dir "$OUTPUT_DIR" --validators "$NUM_VALIDATORS"
if [ "$OUTBE_CONSENSUS_HOST_PATTERN" != "127.0.0.1" ] || [ "$PORT_OFFSET" != "0" ]; then
    echo "  Rewriting consensus/reth p2p endpoints (host pattern: $OUTBE_CONSENSUS_HOST_PATTERN, port offset: $PORT_OFFSET)"
    OUTBE_PORT_OFFSET="$PORT_OFFSET" python3 - \
        "$OUTPUT_DIR/validators.json" \
        "$OUTBE_CONSENSUS_HOST_PATTERN" \
        "$OUTPUT_DIR/reth-bootnodes.txt" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

CONSENSUS_BASE = 30400
offset = int(os.environ.get("OUTBE_PORT_OFFSET", "0"))

validators_path = Path(sys.argv[1])
pattern = sys.argv[2]
bootnodes_path = Path(sys.argv[3])

# Consensus p2p_address: host from the pattern, port shifted by the offset. This
# feeds seed_genesis.py -> the on-chain ValidatorSet, which every node reads to
# resolve consensus peers; it must match run-testnet.sh's --consensus.listen-addr.
validators = json.loads(validators_path.read_text())
for i, entry in enumerate(validators):
    host = pattern.replace("{i}", str(i)).replace("%d", str(i))
    entry["p2p_address"] = f"{host}:{CONSENSUS_BASE + offset + i}"
validators_path.write_text(json.dumps(validators, indent=2) + "\n")

# Reth bootnode enode ports shift by the same offset (identity/host preserved).
# Each line already encodes its validator's base port, so add the offset in place.
if offset and bootnodes_path.exists():
    lines = []
    for line in bootnodes_path.read_text().splitlines():
        m = re.match(r"^(enode://[^@]+@[^:]+:)(\d+)\s*$", line)
        lines.append(f"{m.group(1)}{int(m.group(2)) + offset}" if m else line)
    bootnodes_path.write_text("\n".join(lines) + "\n")
PY
fi
echo

# Step 2: Generate genesis.json
echo "--- Step 2: Generate Genesis ---"

# Extract validator addresses from validators.json
ALLOC=""
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    ADDR=$(python3 -c "
import json, sys
with open('$OUTPUT_DIR/validators.json') as f:
    validators = json.load(f)
print(validators[$i]['address'][2:])  # strip 0x prefix
")
    # 10000 COEN = 10000 * 10^18 = 0x21E19E0C9BAB2400000
    if [ -n "$ALLOC" ]; then
        ALLOC="$ALLOC,"
    fi
    ALLOC="$ALLOC
      \"$ADDR\": { \"balance\": \"0x21E19E0C9BAB2400000\" }"
done

GENESIS_EPOCH=$(date +%s)
GENESIS_TIMESTAMP=$(printf '0x%x' "$GENESIS_EPOCH")
# The metadosis runtime derives the active worldwide-day each block from the block
# timestamp: WorldwideDay::from_timestamp = date_key(ts + UTC_PLUS_14_OFFSET=50400).
# Seed the OFFERING day on that SAME current date so it tracks the chain wall-clock.
# A stale hardcoded day desyncs from the runtime-created "today" and wedges
# metadosis processing (two active days). See seed_genesis.py --worldwide-day.
WORLDWIDE_DAY=$(date -u -d "@$((GENESIS_EPOCH + 50400))" +%Y%m%d 2>/dev/null \
    || date -u -r "$((GENESIS_EPOCH + 50400))" +%Y%m%d)
if date -u -d '1 day ago' +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
    GENESIS_TIME=$(date -u -d '1 day ago' +"%Y-%m-%dT%H:%M:%SZ")
else
    GENESIS_TIME=$(date -u -v-1d +"%Y-%m-%dT%H:%M:%SZ")
fi

cat > "$OUTPUT_DIR/genesis.json" <<GENESIS
{
  "config": {
    "chainId": 54322345,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "mergeNetsplitBlock": 0,
    "terminalTotalDifficulty": 0,
    "terminalTotalDifficultyPassed": true,
    "shanghaiTime": 0,
    "cancunTime": 0,
    "pragueTime": 0,
    "epochLengthBlocks": $TESTNET_EPOCH_LENGTH_BLOCKS,
    "dkgPrepareWindowBlocks": $TESTNET_DKG_PREPARE_WINDOW_BLOCKS,
    "dkgActivationGraceBlocks": $TESTNET_DKG_ACTIVATION_GRACE_BLOCKS,
    "genesisTime": "$GENESIS_TIME"
  },
  "nonce": "0x0",
  "timestamp": "$GENESIS_TIMESTAMP",
  "extraData": "0x",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x0",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "alloc": {$ALLOC
  }
}
GENESIS

echo "  Genesis written to $OUTPUT_DIR/genesis.json"
echo "  Pre-funded $NUM_VALIDATORS validators with 10000 liquid COEN each"
echo

# Step 2b: Seed genesis with precompile storage (optional)
if [ -n "$SEED_FILE" ]; then
    echo "--- Step 2b: Seed Genesis ---"
    echo "  Seed: $SEED_FILE"
    python3 "$SCRIPT_DIR/seed_genesis.py" \
        --genesis "$OUTPUT_DIR/genesis.json" \
        --seed "$SEED_FILE" \
        --validators "$OUTPUT_DIR/validators.json" \
        --worldwide-day "$WORLDWIDE_DAY" \
        --output "$OUTPUT_DIR/genesis.json"
    echo "  Worldwide-day retargeted to genesis date $WORLDWIDE_DAY (tracks wall-clock)"
    echo "  Seeded genesis validator stake from $OUTPUT_DIR/validators.json"
    echo
else
    echo "--- Step 2b: Seed Genesis skipped ---"
    echo "  Warning: validator startup requires ValidatorSet/Staking state in genesis.json"
    echo
fi

# Step 2c: Dev slashing tuning. Felony thresholds default to 150 misses per epoch
# (prod epoch 1200 ≈ 1h; see slashindicator runtime), which exceeds this short dev
# epoch (TESTNET_EPOCH_LENGTH_BLOCKS) so the per-epoch reset would wipe the counter
# before it triggers. Lower them below the dev epoch so downtime slashing is
# observable on localnet. Invariant: felony_threshold < epoch_length.
# SlashIndicator = 0x..EE01; config slot 1 = proposer felony, slot 13 = voter felony.
DEV_FELONY_THRESHOLD="${DEV_FELONY_THRESHOLD:-30}"
if [ "$DEV_FELONY_THRESHOLD" -ge "$TESTNET_EPOCH_LENGTH_BLOCKS" ]; then
    echo "Error: DEV_FELONY_THRESHOLD ($DEV_FELONY_THRESHOLD) must be < epoch length ($TESTNET_EPOCH_LENGTH_BLOCKS)" >&2
    exit 1
fi
python3 - "$OUTPUT_DIR/genesis.json" "$DEV_FELONY_THRESHOLD" <<'PY'
import json, sys
path, thr = sys.argv[1], int(sys.argv[2])
g = json.load(open(path))
alloc = g["alloc"]
key = next((k for k in alloc if k.lower().replace("0x", "").rjust(40, "0").endswith("ee01")), None)
if key is None:
    key = "0x000000000000000000000000000000000000ee01"
    alloc[key] = {"balance": "0x0", "code": "0xef0000"}
st = alloc[key].setdefault("storage", {})
st["0x" + format(1, "064x")] = "0x" + format(thr, "064x")   # config_proposer_felony_threshold
st["0x" + format(13, "064x")] = "0x" + format(thr, "064x")  # config_voter_felony_threshold
json.dump(g, open(path, "w"), indent=2)
PY
echo "  Dev felony thresholds set to $DEV_FELONY_THRESHOLD blocks (< epoch $TESTNET_EPOCH_LENGTH_BLOCKS) for observable localnet slashing"
echo

# Step 3: Print startup commands
echo "--- Startup Commands ---"
echo
BASE_RETH_P2P_PORT=$((30303 + PORT_OFFSET))
BASE_RETH_DISCV5_PORT=$((31303 + PORT_OFFSET))
BASE_CONSENSUS_PORT=$((30400 + PORT_OFFSET))
BASE_RPC_PORT=$((8545 + PORT_OFFSET))
BASE_AUTH_RPC_PORT=$((8551 + PORT_OFFSET))
BASE_METRICS_PORT=$((9101 + PORT_OFFSET))
RETH_BOOTNODES_FILE="${RETH_BOOTNODES_FILE:-$OUTPUT_DIR/reth-bootnodes.txt}"

for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    RETH_P2P_PORT=$((BASE_RETH_P2P_PORT + i))
    RETH_DISCV5_PORT=$((BASE_RETH_DISCV5_PORT + i))
    CONSENSUS_PORT=$((BASE_CONSENSUS_PORT + i))
    RPC_PORT=$((BASE_RPC_PORT + i))
    AUTH_RPC_PORT=$((BASE_AUTH_RPC_PORT + i))
    METRICS_PORT=$((BASE_METRICS_PORT + i))
    VALIDATOR_DIR="$OUTPUT_DIR/validator-$i"

    echo "# Validator $i (RPC=$RPC_PORT, P2P=$RETH_P2P_PORT, Consensus=$CONSENSUS_PORT)"
    echo "$OUTBE_CHAIN_BINARY node \\"
    echo "  --validator \\"
    echo "  --chain $OUTPUT_DIR/genesis.json \\"
    echo "  --datadir $VALIDATOR_DIR/data \\"
    echo "  --http --http.addr 0.0.0.0 --http.port $RPC_PORT \\"
    echo "  --http.api eth,net,web3,outbe \\"
    echo "  --port $RETH_P2P_PORT \\"
    echo "  --discovery.port $RETH_P2P_PORT \\"
    echo "  --discovery.v5.addr 127.0.0.1 \\"
    echo "  --discovery.v5.port $RETH_DISCV5_PORT \\"
    if [ -f "$RETH_BOOTNODES_FILE" ]; then
        echo "  --bootnodes \"\$(grep -v '^[[:space:]]*#' $RETH_BOOTNODES_FILE | paste -sd, -)\" \\"
    fi
    if [ -f "$VALIDATOR_DIR/reth-p2p-secret.hex" ]; then
        echo "  --p2p-secret-key-hex \"\$(tr -d '[:space:]' < $VALIDATOR_DIR/reth-p2p-secret.hex)\" \\"
    fi
    echo "  --authrpc.port $AUTH_RPC_PORT \\"
    echo "  --ipcpath $VALIDATOR_DIR/data/reth.ipc \\"
    echo "  --metrics 0.0.0.0:$METRICS_PORT \\"
    echo "  --log.file.directory $VALIDATOR_DIR/logs \\"
    echo "  --consensus.signing-key $VALIDATOR_DIR/signing-key.hex \\"
    echo "  --validator.evm-key $VALIDATOR_DIR/evm-key.hex \\"
    echo "  --consensus.signing-share $VALIDATOR_DIR/signing-share.hex \\"
    echo "  --consensus.public-polynomial $OUTPUT_DIR/polynomial.hex \\"
    echo "  --consensus.dkg-output $OUTPUT_DIR/dkg-output.hex \\"
    echo "  --consensus.listen-addr 127.0.0.1:$CONSENSUS_PORT \\"
    echo "  --consensus.use-local-defaults"
    echo
done

echo "=== Bootstrap Complete ==="
echo "Genesis:            $OUTPUT_DIR/genesis.json"
echo "Validator tooling:  $OUTPUT_DIR/validators.json"
echo "DKG polynomial:     $OUTPUT_DIR/polynomial.hex"
echo "DKG output:         $OUTPUT_DIR/dkg-output.hex"
echo "Reth bootnodes:     $RETH_BOOTNODES_FILE"
echo "Reth p2p secrets:   per-validator files at validator-N/reth-p2p-secret.hex"
echo
echo "--- Validator EVM Keys ---"
echo "Local dev only: keys printed for convenience; never use outside localnet."
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    VALIDATOR_DIR="$OUTPUT_DIR/validator-$i"
    ADDR=$(python3 -c "
import json
with open('$OUTPUT_DIR/validators.json') as f:
    print(json.load(f)[$i]['address'])
")
    PRIV=$(tr -d '[:space:]' < "$VALIDATOR_DIR/evm-key.hex")
    echo "  validator-$i: address=$ADDR  key_file=$VALIDATOR_DIR/evm-key.hex  private_key=0x$PRIV"
done
echo
echo "Example (local dev only; avoid pasting keys into shared logs):"
echo "  EVM_KEY=\$(tr -d '[:space:]' < $OUTPUT_DIR/validator-0/evm-key.hex) cast send <TO> --value 1ether --private-key \"\$EVM_KEY\" --rpc-url http://localhost:8545"
