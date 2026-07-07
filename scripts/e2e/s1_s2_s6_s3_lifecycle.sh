#!/usr/bin/env bash
# e2e.md lifecycle progression on ONE chain (saves bootstraps):
#   S1  cold full-node sync + tribute offer through TEE (state parity)
#   S2  promote full-node -> validator with reshare (stake -> confirm-ready -> ACTIVE)
#   S6  tribute offer in-flight across the committee change (lands once, parity)
#   S3  validator exit -> reshare down -> node DEMOTES to verifier-follower (stays alive)
#
# Adapted to real behavior (see scripts/e2e/README.md): offer does NOT flip wwd
# status (asserted invariant); activation requires confirm-ready (stale-join guard);
# an exited node demotes to a finalized-follower instead of dying.
E2E_NAME=S1S2S6S3
source "$(dirname "$0")/lib.sh"

e2e_step "S1: cold full-node sync + tribute offer (state parity)"
e2e_cleanup
e2e_bootstrap 4 || { e2e_summary; exit 1; }
e2e_start
V0=$(e2e_v0key)
# wwd status BEFORE any offer (genesis OFFERING day == today's $E2E_WWD, status 2).
WWD_BEFORE=$(cast call 0x000000000000000000000000000000000000100E 'getWorldwideDay(uint32)(uint8,uint8,uint64,uint64,uint64,uint64,uint64,uint256,uint256)' "$E2E_WWD" --rpc-url $RPC0 2>/dev/null | sed -n '2p')
e2e_offer "$V0" 1 && e2e_log "offer accepted (supply 1)"
e2e_assert_eq "committee processed offer (supply)" "1" "$(e2e_supply 8545)"
WWD_AFTER=$(cast call 0x000000000000000000000000000000000000100E 'getWorldwideDay(uint32)(uint8,uint8,uint64,uint64,uint64,uint64,uint64,uint256,uint256)' "$E2E_WWD" --rpc-url $RPC0 2>/dev/null | sed -n '2p')
e2e_assert_eq "wwd status unchanged by offer (time-driven, not offer-driven)" "$WWD_BEFORE" "$WWD_AFTER"

e2e_log "provisioning + launching full-node v5 (REGISTERED, not staked)"
e2e_provision_joiner
e2e_launch_joiner
V5H=$(e2e_wait_height 8549 25 18); e2e_log "v5 synced to h=$V5H (committee $(e2e_h 8545))"
e2e_assert_ge "v5 caught up to tip (head > 20)" "$V5H" 20
e2e_assert_eq "full-node executed the offer in its own enclave (supply parity)" "1" "$(e2e_supply 8549)"
e2e_assert_eq "full-node is NOT a consensus participant" "false" "$(e2e_participant "$V5_ADDR" "$(e2e_url 8549)")"
e2e_assert_eq "active set unchanged by a full-node" "4" "$(e2e_active)"
# state-root parity at a common finalized height.
PN=$(e2e_fin 8549); [ "$PN" = "dn" ] && PN=20
SR_C=$(e2e_stateroot 8545 "$PN"); SR_V=$(e2e_stateroot 8549 "$PN")
e2e_assert_eq "state_root parity committee vs full-node @h$PN" "$SR_C" "$SR_V"

e2e_step "S2: stake -> PENDING -> confirm-ready -> reshare -> ACTIVE"
e2e_stake "$V5_KEY" 1000
sleep 6
e2e_assert_eq "staked joiner is PENDING (status 1)" "1" "$(e2e_status "$V5_ADDR")"
# stale-join guard: PENDING but NOT yet confirmed -> still not a participant.
e2e_assert_eq "PENDING joiner not yet participant (pre-confirm)" "false" "$(e2e_participant "$V5_ADDR")"
e2e_confirm_ready "$V5_KEY"; e2e_log "confirm-ready sent at committee h=$(e2e_h 8545)"

e2e_step "S6: in-flight tribute offer submitted during the reshare window"
V1=$(e2e_vkey 1)
( for t in 1 2 3 4 5; do "$E2E_CLI" tribute offer "$E2E_WWD" --amount 100 --currency 840 --private-key "$V1" --rpc-url "$RPC0" >/dev/null 2>&1; sleep 6; [ "$(e2e_supply 8545)" = "2" ] && break; done ) &
INFLIGHT_PID=$!

e2e_log "waiting for reshare to activate v5 (ACTIVE participant)..."
ACT=false
for i in $(seq 1 70); do
  sleep 10
  CP=$(e2e_participant "$V5_ADDR")
  e2e_log "  committee=$(e2e_h 8545) v5=$(e2e_h 8549) active=$(e2e_active) participant=$CP"
  [ "$CP" = "true" ] && { ACT=true; break; }
done
wait $INFLIGHT_PID 2>/dev/null
e2e_assert "v5 activated (on-chain participant)" "$([ "$ACT" = true ] && echo true || echo false)"
e2e_assert_eq "v5 status ACTIVE (2)" "2" "$(e2e_status "$V5_ADDR")"
e2e_assert_eq "active set grew to 5" "5" "$(e2e_active)"
e2e_assert_eq "in-flight offer landed exactly once (supply 2)" "2" "$(e2e_supply 8545)"
# lockstep PAST activation proves v5 actually has its share and signs (not voteless).
# settle first: the engine restarts for the new epoch and catches up a few blocks.
e2e_log "settling after activation before the lockstep check..."
sleep 30
LOCK=1; PREV=0
for i in $(seq 1 5); do sleep 10; CH=$(e2e_h 8545); VH=$(e2e_h 8549); G=$((CH-VH)); e2e_log "  lockstep committee=$CH v5=$VH gap=$G"; { [ "$G" -gt 3 ] || [ "$VH" -le "$PREV" ]; } 2>/dev/null && LOCK=0; PREV=$VH; done
e2e_assert "v5 advances in lockstep past activation (has a working share)" "$([ "$LOCK" = 1 ] && echo true || echo false)"
e2e_assert_eq "in-flight offer parity on v5's own RPC" "2" "$(e2e_supply 8549)"

e2e_step "S3: deactivate v5 -> reshare down -> DEMOTE to verifier-follower (stays alive)"
e2e_deactivate "$V5_KEY"; sleep 6
e2e_assert_eq "deactivated validator is EXITING (3) immediately" "3" "$(e2e_status "$V5_ADDR")"
e2e_assert_eq "EXITING stays consensus participant until reshare" "true" "$(e2e_participant "$V5_ADDR")"
# activeValidatorCount drops immediately (counts ACTIVE only); the CONSENSUS set
# (ACTIVE + EXITING-with-share) stays 5 until the exclusion reshare activates.
e2e_assert_eq "consensus set still 5 until the exclusion reshare" "5" "$(e2e_consensus_count)"

e2e_log "waiting for the exclusion reshare (5 -> 4) + v5 demotion..."
EXIT_ACT_H=0
for i in $(seq 1 45); do
  sleep 10
  ST=$(e2e_status "$V5_ADDR"); CC=$(e2e_consensus_count); VH=$(e2e_h 8549)
  e2e_log "  committee=$(e2e_h 8545) v5=$VH consensus=$CC status=$ST demoted=$(e2e_joiner_log_has 'demoting to verifier-follower')"
  if [ "$CC" = "4" ] && [ "$ST" = "4" ]; then EXIT_ACT_H=$(e2e_h 8545); break; fi
done
e2e_assert_eq "exited validator is UNBONDING (4)" "4" "$(e2e_status "$V5_ADDR")"
e2e_assert_eq "consensus set shrank to 4" "4" "$(e2e_consensus_count)"
e2e_assert_eq "v5 node DEMOTED to verifier-follower (not dead)" "true" "$(e2e_joiner_log_has 'demoting to verifier-follower of the resharded committee')"
# the node must keep following finality after demotion (head advances past the exclusion activation).
sleep 20
VH2=$(e2e_h 8549)
e2e_assert "demoted node still follows finality (head advanced past exclusion)" "$([ "$VH2" != "dn" ] && [ "$VH2" -gt "$EXIT_ACT_H" ] 2>/dev/null && echo true || echo false)"
# offer parity post-demotion: a new offer is executed by the demoted follower too.
V2=$(e2e_vkey 2)
for t in 1 2 3 4 5; do "$E2E_CLI" tribute offer "$E2E_WWD" --amount 100 --currency 840 --private-key "$V2" --rpc-url "$RPC0" >/dev/null 2>&1; sleep 6; [ "$(e2e_supply 8545)" = "3" ] && break; done
sleep 6
e2e_assert_eq "demoted follower still executes offers (supply parity)" "$(e2e_supply 8545)" "$(e2e_supply 8549)"

e2e_summary
