#!/usr/bin/env bash
# Start, stop, or check status of a local testnet bootstrapped by bootstrap-testnet.sh.
#
# Usage:
#   ./scripts/run-testnet.sh start  <OUTPUT_DIR>
#   ./scripts/run-testnet.sh stop   <OUTPUT_DIR>
#   ./scripts/run-testnet.sh status <OUTPUT_DIR>
#
# Example:
#   ./scripts/bootstrap-testnet.sh 4 /tmp/outbe-testnet
#   ./scripts/run-testnet.sh start  /tmp/outbe-testnet
#   ./scripts/run-testnet.sh status /tmp/outbe-testnet
#   ./scripts/run-testnet.sh stop   /tmp/outbe-testnet

set -euo pipefail

ACTION="${1:?Usage: $0 <start|stop|status> <output_dir>}"
OUTPUT_DIR="${2:?Usage: $0 <start|stop|status> <output_dir>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VALIDATORS_JSON="$OUTPUT_DIR/validators.json"
PID_DIR="$OUTPUT_DIR/pids"
RETH_BOOTNODES="${RETH_BOOTNODES:-}"
RETH_BOOTNODES_FILE="${RETH_BOOTNODES_FILE:-$OUTPUT_DIR/reth-bootnodes.txt}"
# Uniform port shift so multiple localnets can run in parallel. Applied to every
# base port below (and the TEE socket). Must match the PORT_OFFSET the network was
# bootstrapped with — bootstrap-testnet.sh bakes the same shift into the consensus
# p2p addresses (validators.json/genesis) and reth bootnodes.
PORT_OFFSET="${PORT_OFFSET:-0}"
OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR="${OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR:-}"
OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT="${OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT:-}"
OUTBE_TEST_VOTING_WINDOW_BLOCKS="${OUTBE_TEST_VOTING_WINDOW_BLOCKS:-}"

# --- Helpers ---

num_validators() {
    python3 -c "import json; print(len(json.load(open('$VALIDATORS_JSON'))))"
}

locate_binary() {
    if [ -n "${OUTBE_CHAIN_BINARY:-}" ]; then
        if [ ! -x "$OUTBE_CHAIN_BINARY" ]; then
            echo "Error: OUTBE_CHAIN_BINARY is set but not executable: $OUTBE_CHAIN_BINARY"
            exit 1
        fi
        echo "Using outbe-chain binary: $OUTBE_CHAIN_BINARY"
        return
    fi

    for candidate in ./target/debug/outbe-chain ./target/release/outbe-chain; do
        if [ -x "$candidate" ]; then
            OUTBE_CHAIN_BINARY="$candidate"
            echo "Using outbe-chain binary: $OUTBE_CHAIN_BINARY"
            return
        fi
    done

    echo "Error: outbe-chain binary not found. Run 'cargo build --bin outbe-chain' or set OUTBE_CHAIN_BINARY."
    exit 1
}

load_bootnodes() {
    if [ -n "$RETH_BOOTNODES" ]; then
        printf '%s' "$RETH_BOOTNODES"
        return
    fi

    if [ -f "$RETH_BOOTNODES_FILE" ]; then
        RETH_BOOTNODES_FILE="$RETH_BOOTNODES_FILE" python3 -c '
import os
from pathlib import Path

path = Path(os.environ["RETH_BOOTNODES_FILE"])
nodes = [
    line.strip()
    for line in path.read_text().splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]
print(",".join(nodes), end="")
'
    fi
}

# --- Commands ---

do_start() {
    if [ ! -f "$VALIDATORS_JSON" ]; then
        echo "Error: $VALIDATORS_JSON not found. Run bootstrap-testnet.sh first."
        exit 1
    fi

    locate_binary
    mkdir -p "$PID_DIR"

    # WS-M2 M5: re-apply TEE flags persisted by a previous start for any var the
    # caller did not set this time, so a restart stays consistent. Dropping
    # OUTBE_TEE_SEAL across a restart would halt every node (expected seal vs none);
    # dropping OUTBE_TEE_ENCLAVE would silently resume the chain WITHOUT TEE. An
    # explicit env var still wins (the file uses `:=`, set-if-unset). Remove the file
    # (or `localnet-clean`) to switch modes.
    local tee_env_file="$OUTPUT_DIR/tee-env"
    if [ -f "$tee_env_file" ]; then
        # shellcheck disable=SC1090
        . "$tee_env_file"
    fi

    local n
    n=$(num_validators)
    echo "Starting $n validators from $OUTPUT_DIR"

    local bootnodes
    bootnodes="$(load_bootnodes)"
    if [ -n "$bootnodes" ]; then
        if [ -n "$RETH_BOOTNODES" ]; then
            echo "Using Reth bootnodes from RETH_BOOTNODES"
        else
            echo "Using Reth bootnodes from $RETH_BOOTNODES_FILE"
        fi
    fi

    local base_rpc=$((8545 + PORT_OFFSET))
    local base_p2p=$((30303 + PORT_OFFSET))
    local base_discv5=$((31303 + PORT_OFFSET))
    local base_consensus=$((30400 + PORT_OFFSET))
    local base_authrpc=$((8551 + PORT_OFFSET))
    local base_metrics=$((9101 + PORT_OFFSET))

    # Optional per-validator TEE enclave. Opt-in via OUTBE_TEE_ENCLAVE=1 (binary
    # auto-detected in ./target, or set OUTBE_TEE_ENCLAVE_BINARY). When enabled,
    # each validator runs its own `outbe-tee-enclave` AS A REAL GRAMINE ENCLAVE
    # (signed; gramine-direct locally, gramine-sgx on SGX hardware) and the node
    # attests it at startup (--tee-enclave-socket; node fail-fasts if it is down).
    local tee_enclave_bin=""
    local tee_gramine_image="outbe-tee-enclave-gramine"
    if [ -n "${OUTBE_TEE_ENCLAVE:-}" ]; then
        # OUTBE_TEE_ENCLAVE_MOCK=1 selects the dev mock binary
        # (`outbe-tee-enclave-mock`, built `--features mock`): unattested quote +
        # stable sealing key, for localnet/CI without SGX. Node args are identical
        # — only which binary the container runs differs.
        local tee_bin_name="outbe-tee-enclave"
        local tee_build_hint="cargo build --bin outbe-tee-enclave"
        if [ -n "${OUTBE_TEE_ENCLAVE_MOCK:-}" ]; then
            tee_bin_name="outbe-tee-enclave-mock"
            tee_build_hint="cargo build --bin outbe-tee-enclave-mock --features mock"
        fi
        tee_enclave_bin="${OUTBE_TEE_ENCLAVE_BINARY:-}"
        if [ -z "$tee_enclave_bin" ]; then
            for cand in "./target/debug/$tee_bin_name" "./target/release/$tee_bin_name"; do
                if [ -x "$cand" ]; then tee_enclave_bin="$cand"; break; fi
            done
        fi
        if [ -z "$tee_enclave_bin" ]; then
            echo "Error: OUTBE_TEE_ENCLAVE set but $tee_bin_name binary not found." >&2
            echo "  Build it ($tee_build_hint) or set OUTBE_TEE_ENCLAVE_BINARY." >&2
            exit 1
        fi
        # The enclave runs only under Gramine — Docker + the gramine image are
        # required. Build the image automatically if it is missing.
        if ! command -v docker >/dev/null 2>&1; then
            echo "Error: OUTBE_TEE_ENCLAVE needs Docker to run the Gramine enclave." >&2
            echo "  Install Docker, or run without OUTBE_TEE_ENCLAVE for a non-TEE testnet." >&2
            exit 1
        fi
        if ! docker info >/dev/null 2>&1; then
            echo "Error: Docker is installed but not reachable by this user." >&2
            echo "  Add your user to the 'docker' group (sudo usermod -aG docker \$USER; re-login)," >&2
            echo "  or run this script under sudo (note: it makes the validator data dirs root-owned)." >&2
            exit 1
        fi
        if ! docker image inspect "$tee_gramine_image" >/dev/null 2>&1; then
            echo "Gramine enclave image '$tee_gramine_image' missing — building it..."
            if ! docker build -t "$tee_gramine_image" bin/outbe-tee-enclave/gramine; then
                echo "Error: failed to build the Gramine enclave image." >&2
                exit 1
            fi
        fi
        echo "TEE enclave enabled ($tee_bin_name; Gramine: gramine-direct locally / gramine-sgx on SGX hw): $tee_enclave_bin"
        # WS-M2 M5: persist the resolved TEE flags so a later `start` that omits them
        # stays consistent with this one (see the re-apply note at the top of do_start).
        {
            printf ': "${OUTBE_TEE_ENCLAVE:=%s}"\n' "${OUTBE_TEE_ENCLAVE:-}"
            printf ': "${OUTBE_TEE_ENCLAVE_MOCK:=%s}"\n' "${OUTBE_TEE_ENCLAVE_MOCK:-}"
            printf ': "${OUTBE_TEE_SEAL:=%s}"\n' "${OUTBE_TEE_SEAL:-}"
        } > "$tee_env_file"
    fi

    local launched=()
    for i in $(seq 0 $((n - 1))); do
        local pid_file="$PID_DIR/validator-$i.pid"

        if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
            echo "  Validator $i already running (PID $(cat "$pid_file")), skipping"
            continue
        fi

        local validator_dir="$OUTPUT_DIR/validator-$i"
        local log_file="$validator_dir/node.log"
        local exit_file="$validator_dir/node.exit"
        local reth_log_dir="$validator_dir/logs"

        # Clean stale lock file
        rm -f "$validator_dir/data/db/lock"
        rm -f "$exit_file"
        mkdir -p "$reth_log_dir"

        # Launch this validator's TEE enclave and wait for its socket so the node
        # can attest it at startup. The enclave ALWAYS runs as a real Gramine
        # enclave (signed, measured MRENCLAVE) — never as a bare process:
        #   - no SGX hardware (local dev) -> gramine-direct, for functional tests,
        #   - SGX hardware present (prod/testnet) -> gramine-sgx, confidential.
        # The entrypoint picks the mode automatically; we just pass the SGX device
        # through when it exists. Gramine pathname UDS are process-internal, so the
        # node reaches the enclave over TCP (--network host puts the port on the
        # host loopback). One container per validator.
        local -a tee_args=()
        if [ -n "$tee_enclave_bin" ]; then
            # Distinct DKG identity per validator (else the n enclaves would be
            # the same DKG participant — a degenerate ceremony). Deterministic
            # from the validator index; a validator-count/order change requires a
            # clean re-bootstrap. Offset by 1 so the seed is never all-zero.
            local tee_dkg_seed
            tee_dkg_seed=$(printf '%064x' "$((i + 1))")
            local tee_port=$((7000 + PORT_OFFSET + i))
            local tee_endpoint="127.0.0.1:$tee_port"
            # Tag the container with PORT_OFFSET so parallel localnets get
            # distinct names (`outbe-tee-gramine-<offset>-<i>`) and each run only
            # tears down its own enclaves.
            local tee_ctr="outbe-tee-gramine-${PORT_OFFSET}-$i"
            local -a sgx_dev=()
            # Pass the SGX device only for the production binary. In mock mode the
            # enclave is the EMULATOR (gramine-direct, no SGX): withholding the
            # device makes the entrypoint pick gramine-direct, and the `mock`
            # feature supplies a stable sealing key so the restart fast-path is
            # still testable without SGX.
            if [ -z "${OUTBE_TEE_ENCLAVE_MOCK:-}" ]; then
                if [ -e /dev/sgx_enclave ] || [ -e /dev/sgx/enclave ]; then
                    sgx_dev=(--device /dev/sgx_enclave)
                    # Provisioning device + AESM socket: gramine-sgx may need them
                    # at enclave load (even with remote_attestation = "none"). Pass
                    # them through when present; harmless otherwise.
                    [ -e /dev/sgx_provision ] && sgx_dev+=(--device /dev/sgx_provision)
                    [ -S /var/run/aesmd/aesm.socket ] &&
                        sgx_dev+=(-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket)
                fi
            fi
            # OUTBE_TEE_SEAL=1 enables the sealed restart fast-path: the enclave
            # seals its DKG-derived offer key + share to a PERSISTENT per-validator
            # dir (survives container restart), so a stop/start restores the offer
            # key from seal (real EGETKEY under gramine-sgx) instead of re-running
            # the ceremony — which the node skips on a non-fresh chain. Needs SGX
            # (no EGETKEY under gramine-direct → sealing is a no-op).
            local -a tee_seal_mount=() tee_seal_args=()
            if [ -n "${OUTBE_TEE_SEAL:-}" ]; then
                local tee_data_dir="$validator_dir/tee"
                mkdir -p "$tee_data_dir"
                local tee_chain_hex
                tee_chain_hex=0x$(printf '%064x' "$(python3 -c "import json;print(json.load(open('$OUTPUT_DIR/genesis.json'))['config']['chainId'])")")
                tee_seal_mount=(-v "$(readlink -f "$tee_data_dir"):/tee")
                tee_seal_args=(--tee-dir /tee --chain-id "$tee_chain_hex")
            fi
            # DKG identity source. The mock (gramine-direct, no EGETKEY) uses a
            # deterministic per-index --dkg-seed. Real gramine-sgx WITH sealing
            # (OUTBE_TEE_SEAL) instead lets the enclave SELF-GENERATE and seal its
            # identity (survives restart), so NO host seed is supplied.
            local -a tee_dkg_arg=(--dkg-seed "$tee_dkg_seed")
            if [ -z "${OUTBE_TEE_ENCLAVE_MOCK:-}" ] && [ -n "${OUTBE_TEE_SEAL:-}" ]; then
                tee_dkg_arg=()
            fi
            docker rm -f "$tee_ctr" >/dev/null 2>&1 || true
            docker run -d --name "$tee_ctr" \
                --security-opt seccomp=unconfined \
                --network host \
                "${sgx_dev[@]}" \
                "${tee_seal_mount[@]}" \
                -v "$(readlink -f "$tee_enclave_bin"):/app/outbe-tee-enclave:ro" \
                outbe-tee-enclave-gramine \
                --socket "$tee_endpoint" "${tee_dkg_arg[@]}" "${tee_seal_args[@]}" >/dev/null
            echo "$tee_ctr" > "$PID_DIR/validator-$i.enclave.docker"
            local tee_up=""
            for _ in $(seq 1 200); do
                (exec 3<>"/dev/tcp/127.0.0.1/$tee_port") 2>/dev/null && { exec 3>&- 2>/dev/null; tee_up=1; break; }
                sleep 0.1
            done
            docker logs "$tee_ctr" > "$validator_dir/enclave.log" 2>&1 || true
            # WS-M2 M6: fail loudly instead of silently proceeding — otherwise the node
            # would later fail-fast on the missing socket with a less obvious cause.
            if [ -z "$tee_up" ]; then
                echo "Error: validator-$i TEE enclave ($tee_ctr) did not open its socket 127.0.0.1:$tee_port within ~20s." >&2
                echo "  The node would fail-fast on the missing socket. Enclave output: $validator_dir/enclave.log" >&2
                docker rm -f "$tee_ctr" >/dev/null 2>&1 || true
                exit 1
            fi
            tee_args+=(--tee-enclave-socket "$tee_endpoint")
        fi

        local -a reth_p2p_args=()
        if [ -n "$bootnodes" ]; then
            reth_p2p_args+=(--bootnodes "$bootnodes")
        fi
        if [ -f "$validator_dir/reth-p2p-secret.hex" ]; then
            local reth_p2p_secret
            reth_p2p_secret="$(tr -d '[:space:]' < "$validator_dir/reth-p2p-secret.hex")"
            reth_p2p_args+=(--p2p-secret-key-hex "$reth_p2p_secret")
        fi

        local -a consensus_material_args=()
        # if [ -f "$validator_dir/signing-share.hex" ] \
        #     && [ -f "$OUTPUT_DIR/polynomial.hex" ] \
        #     && [ -f "$OUTPUT_DIR/dkg-output.hex" ]; then
        #     consensus_material_args+=(
        #         --consensus.signing-share "$validator_dir/signing-share.hex"
        #         --consensus.public-polynomial "$OUTPUT_DIR/polynomial.hex"
        #         --consensus.dkg-output "$OUTPUT_DIR/dkg-output.hex"
        #     )
        # fi

        local -a cmd=(
            "$OUTBE_CHAIN_BINARY" node
            --validator
            --chain "$OUTPUT_DIR/genesis.json"
            --datadir "$validator_dir/data"
            --http --http.addr 0.0.0.0 --http.port $((base_rpc + i))
            --http.api eth,net,web3,outbe
            --port $((base_p2p + i))
            --discovery.port $((base_p2p + i))
            --discovery.v5.addr 127.0.0.1
            --discovery.v5.port $((base_discv5 + i))
        )
        if [ ${#reth_p2p_args[@]} -gt 0 ]; then
            cmd+=("${reth_p2p_args[@]}")
        fi
        cmd+=(
            --authrpc.port $((base_authrpc + i))
            --ipcpath "$validator_dir/data/reth.ipc"
            --metrics "0.0.0.0:$((base_metrics + i))"
            --log.file.directory "$reth_log_dir"
            --consensus.signing-key "$validator_dir/signing-key.hex"
            --validator.evm-key "$validator_dir/evm-key.hex"
        )
        if [ ${#consensus_material_args[@]} -gt 0 ]; then
            cmd+=("${consensus_material_args[@]}")
        fi
        cmd+=(
            --consensus.listen-addr "127.0.0.1:$((base_consensus + i))"
            --consensus.use-local-defaults
        )
        if [ ${#tee_args[@]} -gt 0 ]; then
            cmd+=("${tee_args[@]}")
        fi
        # Debug builds need a larger thread stack: on block 1 the proposer signs
        # the begin-zone system txs, which lazily initializes k256's secp256k1
        # generator lookup table — a huge *unoptimized* stack frame that
        # overflows reth's ~2 MiB tokio blocking-pool thread (`thread '<unknown>'
        # has overflowed its stack`). Release builds optimize the frame away and
        # are unaffected. 16 MiB is ample headroom; operators may override.
        local -a env_args=(RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}")
        if [ -n "$OUTBE_TEST_VOTING_WINDOW_BLOCKS" ]; then
            env_args+=(OUTBE_TEST_VOTING_WINDOW_BLOCKS="$OUTBE_TEST_VOTING_WINDOW_BLOCKS")
            echo "  Validator $i test hook: voting window $OUTBE_TEST_VOTING_WINDOW_BLOCKS blocks"
        fi
        if [ -n "$OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR" ] \
            && [ -n "$OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT" ] \
            && [ "$OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR" = "$i" ]; then
            env_args+=(OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT="$OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT")
            echo "  Validator $i test hook: drop new_payload at height $OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT"
        elif [ -n "$OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT" ]; then
            env_args+=(OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT=)
        fi

        if [ ${#env_args[@]} -gt 0 ]; then
            nohup "$SCRIPT_DIR/run-supervised.sh" "$exit_file" env "${env_args[@]}" "${cmd[@]}" > "$log_file" 2>&1 < /dev/null &
        else
            nohup "$SCRIPT_DIR/run-supervised.sh" "$exit_file" "${cmd[@]}" > "$log_file" 2>&1 < /dev/null &
        fi

        local pid=$!
        echo "$pid" > "$pid_file"
        echo "  Validator $i started (PID $pid, log: $log_file)"
        launched+=("$i:$pid:$log_file")
    done

    # Verify the launched processes survived startup. Reth fails fast on
    # genesis-hash / DB mismatches and similar configuration errors, and a
    # backgrounded process that exits before we exit makes the launch look
    # successful. Sleep briefly, then re-check each PID.
    if [ ${#launched[@]} -gt 0 ]; then
        sleep 2
        local failed=0
        for entry in "${launched[@]}"; do
            local i="${entry%%:*}"
            local rest="${entry#*:}"
            local pid="${rest%%:*}"
            local log="${rest#*:}"
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "  ERROR: Validator $i (PID $pid) exited during startup."
                echo "  --- Last lines of $log ---"
                tail -n 20 "$log" | sed 's/^/    /'
                echo "  --- end of log tail ---"
                rm -f "$PID_DIR/validator-$i.pid"
                failed=$((failed + 1))
            fi
        done
        if [ "$failed" -gt 0 ]; then
            echo "Error: $failed validator(s) failed to start. See logs above."
            exit 1
        fi
    fi

    echo "All validators launched. Use '$0 status $OUTPUT_DIR' to check."
}

do_stop() {
    if [ ! -d "$PID_DIR" ]; then
        echo "No PID directory found at $PID_DIR — nothing to stop."
        exit 0
    fi

    # Graceful shutdown: SIGTERM every node, then WAIT for each to exit before
    # tearing down enclaves/locks. A node must flush its execution AND consensus
    # (marshal) stores atomically on shutdown; killing it (or yanking its enclave)
    # mid-flush leaves execution one block ahead of consensus, which fails the next
    # restart with "marshal finalization missing for finalized execution height N".
    local -a stopping_pids=() stopping_names=()
    for pid_file in "$PID_DIR"/validator-*.pid; do
        [ -f "$pid_file" ] || continue
        local name pid
        name=$(basename "$pid_file" .pid)
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
            stopping_pids+=("$pid")
            stopping_names+=("$name")
            echo "  Stopping $name (PID $pid) — waiting for clean shutdown..."
        else
            echo "  $name (PID $pid) already dead"
        fi
        rm -f "$pid_file"
    done
    # Wait up to ~60s per node for a clean exit; SIGKILL only as a last resort.
    local idx
    for idx in "${!stopping_pids[@]}"; do
        local pid="${stopping_pids[$idx]}" name="${stopping_names[$idx]}"
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 600 ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo "  $name did not exit in 60s — SIGKILL (restart may need resync)"
            # $pid is the run-supervised.sh wrapper; SIGKILL cannot be forwarded
            # to its node child, which would orphan a still-running reth process
            # holding the MDBX/static_files locks and fail the next restart with
            # "storage directory in use". Kill the child first, then the wrapper.
            pkill -KILL -P "$pid" 2>/dev/null || true
            kill -KILL "$pid" 2>/dev/null
        else
            echo "  Stopped $name"
        fi
    done

    # Stop any gramine-direct enclave containers (OUTBE_TEE_GRAMINE=1) — AFTER the
    # nodes have exited, so a node is never mid-request to an enclave being removed.
    for dfile in "$PID_DIR"/validator-*.enclave.docker; do
        [ -f "$dfile" ] || continue
        local ctr
        ctr=$(cat "$dfile")
        docker rm -f "$ctr" >/dev/null 2>&1 && echo "  Stopped enclave container $ctr"
        rm -f "$dfile"
    done

    # Clean stale lock files (both the MDBX `db/lock` and reth's
    # `static_files/lock`) so a fast restart does not hit "storage directory in
    # use" if a node was SIGKILLed without releasing them.
    for lock in "$OUTPUT_DIR"/validator-*/data/db/lock \
        "$OUTPUT_DIR"/validator-*/data/static_files/lock; do
        [ -f "$lock" ] && rm -f "$lock"
    done

    echo "All validators stopped."
}

do_status() {
    if [ ! -d "$PID_DIR" ]; then
        echo "No PID directory found — testnet not started."
        exit 0
    fi

    for pid_file in "$PID_DIR"/validator-*.pid; do
        [ -f "$pid_file" ] || continue
        local name
        name=$(basename "$pid_file" .pid)
        local pid
        pid=$(cat "$pid_file")

        if kill -0 "$pid" 2>/dev/null; then
            echo "  $name: running (PID $pid)"
        else
            echo "  $name: dead (PID $pid)"
        fi
    done
}

# --- Main ---

case "$ACTION" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    *)
        echo "Unknown action: $ACTION"
        echo "Usage: $0 <start|stop|status> <output_dir>"
        exit 1
        ;;
esac
