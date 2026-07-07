#!/usr/bin/env bash
# e2e.md S5 — DKG/reshare failure at join (negative).
#
# Adapted (README.md): there is NO "24 retries hourly -> hard halt" model. The real
# bound is VRF expiry (planned_activation + activation_grace_blocks); while a join
# reshare keeps failing, the OLD committee keeps finalizing (simplex quorum) until
# that height. Retry is per-finalized-height (flag-based), with no retry counter.
#
# Setup: freeze a 4->5 target (joiner confirmed), then take online acking players
# below player_threshold (kill joiner + one old validator => 3 online < 4) so the
# ceremony cannot complete. Assert: retry log repeats, chain stays live via 3-of-4
# simplex quorum, no hard-halt; then restore the killed validator -> ceremony
# completes on a later retry and the set reaches 5.
E2E_NAME=S5
source "$(dirname "$0")/lib.sh"

# Widen the DKG activation grace so the VRF window outlasts a long failed reshare.
# With the default grace (30) the VRF expires at planned_activation(120)+30 = 150,
# which is exactly when the first ceremony timeout (~h90 freeze + 120s) lands — the
# chain soft-halts at the VRF-expiry bound (the e2e.md "soft halt") before a
# restored validator can catch up and re-ack. A wide grace keeps the OLD committee
# live long enough to demonstrate RECOVERY ("после восстановления reshare
# завершается"). The small-grace soft-halt is the alternative ("ИЛИ корректный
# halt") and was observed separately (chain halts at h150).
export TESTNET_DKG_ACTIVATION_GRACE_BLOCKS=600

e2e_step "S5: bootstrap + freeze a 4->5 reshare target (wide VRF grace for recovery)"
e2e_cleanup
e2e_bootstrap 4 || { e2e_summary; exit 1; }
e2e_start
e2e_provision_joiner
e2e_launch_joiner
e2e_wait_height 8549 25 18 >/dev/null
e2e_stake "$V5_KEY" 1000; sleep 6
e2e_confirm_ready "$V5_KEY"

e2e_step "S5: take players offline BEFORE the reshare ceremony so it cannot complete"
# The ceremony's ack phase completes within seconds of the freeze, so killing
# players AFTER the freeze is too late (they may already have acked). Instead take
# the joiner v5 AND one old player (validator-3) offline NOW, before the freeze, so
# the 4->5 ceremony begins with only 3 online players {v0,v1,v2} < player_threshold
# (quorum(5)=4) for its whole life. Two unavailable players (v3 + v5) also exceed
# the single allowed dealer reveal, so the ceremony cannot complete. Meanwhile the
# CURRENT committee is {v0,v1,v2,v3}; with v3 down, online = 3 = quorum(4), so the
# chain keeps finalizing (BFT liveness) while the join reshare fails.
e2e_stop_joiner
e2e_kill_validator 3
KILL_H=$(e2e_h 8545)
e2e_log "took v5 + validator-3 offline at committee h=$KILL_H (before the freeze); observing the failed reshare..."
RETRY=0; ALIVE_GROW=false
for i in $(seq 1 30); do
  sleep 10
  H=$(e2e_h 8545)
  RETRY=$(e2e_val_log_count 0 'DKG reshare failed, retrying frozen target')
  e2e_log "  survivor head=$H retry_count=$RETRY active=$(e2e_active)"
  { [ "$H" != "dn" ] && [ "$H" -gt $((KILL_H+12)) ] 2>/dev/null; } && ALIVE_GROW=true
  [ "$RETRY" -ge 1 ] 2>/dev/null && [ "$ALIVE_GROW" = true ] && break
done
e2e_assert_ge "DKG join-reshare retried (flag-based, per finalized height)" "$RETRY" 1
e2e_assert "OLD committee keeps finalizing through the failure (3-of-4 quorum)" "$([ "$ALIVE_GROW" = true ] && echo true || echo false)"
# no hard-halt model: the bound is VRF expiry, not a 24-retry counter.
e2e_assert_eq "no '24 retries / hard halt' soft/hard-halt model exists" "0" "$(e2e_val_log_count 0 'hard halt')"
e2e_assert_eq "join did NOT activate while its reshare is failing (set still 4)" "4" "$(e2e_active)"

e2e_step "S5: restore validator-3 -> ceremony completes on a later retry"
# Relaunch only the downed validator-3 (its supervisor died, so run-testnet's start
# sees a dead pid and re-launches it; live validators are skipped). v5 stays down,
# so on completion it is activated revealed (ACTIVE-but-voteless until it restarts).
sudo env OUTBE_TEE_ENCLAVE=1 OUTBE_TEE_ENCLAVE_MOCK=1 OUTBE_TEE_SEAL=1 \
  OUTBE_TEE_ENCLAVE_BINARY="$E2E_MOCK" OUTBE_CHAIN_BINARY="$E2E_BIN" PATH="$PATH" \
  E2E_PORT_OFFSET="$E2E_PORT_OFFSET" E2E_TAG="$E2E_TAG" \
  ./scripts/run-testnet.sh start "$E2E_DIR" >"${E2E_LOG_PREFIX}-s5-restart.log" 2>&1
e2e_log "restored validator-3; waiting for the ceremony to complete (4 online acking players)..."
RECOVERED=false
for i in $(seq 1 40); do sleep 10; AC=$(e2e_active); e2e_log "  committee=$(e2e_h 8545) active=$AC"; [ "$AC" = "5" ] && { RECOVERED=true; break; }; done
e2e_assert "reshare completes after the participant is restored (set reaches 5)" "$([ "$RECOVERED" = true ] && echo true || echo false)"

e2e_summary
