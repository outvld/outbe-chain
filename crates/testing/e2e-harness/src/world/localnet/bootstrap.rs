//! Bootstrap glue (ported `bootstrap-testnet.sh`): keys/DKG + genesis. The heavy
//! lifting stays one-shot subprocesses (`outbe-chain dkg bootstrap` and
//! `python3 seed_genesis.py`); the genesis skeleton, port rewrite, and dev felony
//! patch are native Rust.

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use eyre::{bail, eyre, Result, WrapErr};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{worldwide_day, Localnet};

/// 10000 COEN (`10000 * 10^18`) as hex — the per-validator liquid balance.
const VALIDATOR_BALANCE_HEX: &str = "0x21E19E0C9BAB2400000";
/// Dev felony threshold (blocks) so downtime slashing is observable on the short
/// localnet epoch; must stay `<` the epoch length (`bootstrap-testnet.sh:234`).
const DEV_FELONY_THRESHOLD: u64 = 30;

impl Localnet {
    /// Bootstrap an N-validator set (keys, DKG, genesis). Runs unprivileged.
    /// `outbe-chain dkg bootstrap` and `seed_genesis.py` stay one-shot
    /// subprocesses; the genesis skeleton, port rewrite, and felony patch are
    /// native. `tuning` forwards `TESTNET_*` knobs (epoch length, DKG grace) some
    /// flows override; pass `&[]` for the defaults.
    pub fn bootstrap(&self, n: usize, tuning: &[(&str, String)]) -> Result<()> {
        fs::create_dir_all(&self.cfg.dir)?;

        // Step 1: DKG bootstrap — keys, polynomial, dkg-output, validators.json,
        // reth-bootnodes.txt.
        let mut cmd = Command::new(&self.cfg.bin_chain);
        cmd.args([
            "dkg",
            "bootstrap",
            "--output-dir",
            &self.dir(),
            "--validators",
            &n.to_string(),
        ]);
        for (k, v) in tuning {
            cmd.env(k, v);
        }
        self.run_setup(&mut cmd, "outbe-chain dkg bootstrap")?;

        // Step 1b: point the baked consensus/reth p2p endpoints at the resolved
        // ports (a no-op under the default layout).
        self.rewrite_ports()?;

        // Step 2: genesis skeleton (chain config + validator balances).
        self.write_genesis(tuning)?;

        // Step 2b: seed precompile storage (validator set/staking/etc.).
        self.seed_genesis(&worldwide_day())?;

        // Step 2c: dev felony thresholds for observable localnet slashing.
        self.patch_felony(tuning)?;
        Ok(())
    }

    /// Rewrite `validators.json` `p2p_address` to the resolved consensus port and
    /// each `reth-bootnodes.txt` enode's port to the resolved p2p port
    /// (`bootstrap-testnet.sh:105-128`).
    fn rewrite_ports(&self) -> Result<()> {
        let vpath = self.cfg.dir.join("validators.json");
        let mut v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&vpath)?)?;
        let arr = v
            .as_array_mut()
            .ok_or_else(|| eyre!("validators.json is not an array"))?;
        for (i, e) in arr.iter_mut().enumerate() {
            if let Some(obj) = e.as_object_mut() {
                obj.insert(
                    "p2p_address".into(),
                    json!(format!("127.0.0.1:{}", self.cfg.consensus_port(i))),
                );
            }
        }
        fs::write(&vpath, serde_json::to_string_pretty(&v)? + "\n")?;

        let bpath = self.cfg.dir.join("reth-bootnodes.txt");
        if let Ok(raw) = fs::read_to_string(&bpath) {
            let mut out = String::new();
            for (i, line) in raw.lines().filter(|l| !l.trim().is_empty()).enumerate() {
                // enode://<id>@<host>:<port> — swap the trailing port for p2p[i].
                match line.trim().rsplit_once(':') {
                    Some((head, _)) => {
                        out.push_str(head);
                        out.push_str(&format!(":{}\n", self.cfg.p2p_port(i)));
                    }
                    None => {
                        out.push_str(line.trim());
                        out.push('\n');
                    }
                }
            }
            fs::write(&bpath, out)?;
        }
        Ok(())
    }

    /// Write the genesis skeleton: static chain config (chain id 54322345, epoch /
    /// DKG params from `tuning`) plus a pre-funded `alloc` of each validator
    /// address (`bootstrap-testnet.sh:133-203`).
    fn write_genesis(&self, tuning: &[(&str, String)]) -> Result<()> {
        let epoch = tuned(tuning, "TESTNET_EPOCH_LENGTH_BLOCKS", 120);
        let dkg_prepare = tuned(tuning, "TESTNET_DKG_PREPARE_WINDOW_BLOCKS", 30);
        let dkg_grace = tuned(tuning, "TESTNET_DKG_ACTIVATION_GRACE_BLOCKS", 30);

        let vjson: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(self.cfg.dir.join("validators.json"))?)?;
        let arr = vjson
            .as_array()
            .ok_or_else(|| eyre!("validators.json is not an array"))?;
        let mut alloc = serde_json::Map::new();
        for e in arr {
            let addr = e
                .get("address")
                .and_then(|a| a.as_str())
                .ok_or_else(|| eyre!("validator entry missing address"))?;
            // Genesis alloc keys are the address without the `0x` prefix.
            let key = addr.trim_start_matches("0x").to_string();
            alloc.insert(key, json!({ "balance": VALIDATOR_BALANCE_HEX }));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // genesisTime is one day in the past so the chain can produce immediately.
        let genesis_time = OffsetDateTime::from_unix_timestamp(now as i64 - 86_400)
            .wrap_err("genesis time")?
            .format(&Rfc3339)
            .wrap_err("format genesis time")?;

        let genesis = json!({
            "config": {
                "chainId": 54_322_345,
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
                "epochLengthBlocks": epoch,
                "dkgPrepareWindowBlocks": dkg_prepare,
                "dkgActivationGraceBlocks": dkg_grace,
                "genesisTime": genesis_time,
            },
            "nonce": "0x0",
            "timestamp": format!("0x{now:x}"),
            "extraData": "0x",
            "gasLimit": "0x1c9c380",
            "difficulty": "0x0",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "alloc": alloc,
        });
        fs::write(
            self.cfg.dir.join("genesis.json"),
            serde_json::to_string_pretty(&genesis)? + "\n",
        )?;
        Ok(())
    }

    /// Seed precompile storage into genesis (`bootstrap-testnet.sh:209-226`) via
    /// the kept `scripts/seed_genesis.py`.
    fn seed_genesis(&self, worldwide_day: &str) -> Result<()> {
        let genesis = self.cfg.dir.join("genesis.json");
        let mut cmd = Command::new("python3");
        cmd.arg(self.cfg.repo.join("scripts/seed_genesis.py"))
            .arg("--genesis")
            .arg(&genesis)
            .arg("--seed")
            .arg(&self.cfg.seed)
            .arg("--validators")
            .arg(self.cfg.dir.join("validators.json"))
            .arg("--worldwide-day")
            .arg(worldwide_day)
            .arg("--output")
            .arg(&genesis);
        self.run_setup(&mut cmd, "seed_genesis.py")
    }

    /// Lower the SlashIndicator felony thresholds so downtime slashing triggers
    /// within the short dev epoch (`bootstrap-testnet.sh:228-253`).
    fn patch_felony(&self, tuning: &[(&str, String)]) -> Result<()> {
        let epoch = tuned(tuning, "TESTNET_EPOCH_LENGTH_BLOCKS", 120);
        if DEV_FELONY_THRESHOLD >= epoch {
            bail!("dev felony threshold {DEV_FELONY_THRESHOLD} must be < epoch length {epoch}");
        }
        let path = self.cfg.dir.join("genesis.json");
        let mut g: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        let alloc = g
            .get_mut("alloc")
            .and_then(|a| a.as_object_mut())
            .ok_or_else(|| eyre!("genesis has no alloc object"))?;

        // SlashIndicator lives at 0x…ee01 (config slot 1 = proposer felony, slot
        // 13 = voter felony). Match the address however it's spelled in alloc.
        let key = alloc.keys().find(|k| ends_with_ee01(k)).cloned();
        let key = key.unwrap_or_else(|| {
            let k = "0x000000000000000000000000000000000000ee01".to_string();
            alloc.insert(k.clone(), json!({ "balance": "0x0", "code": "0xef0000" }));
            k
        });
        let entry = alloc
            .get_mut(&key)
            .and_then(|e| e.as_object_mut())
            .ok_or_else(|| eyre!("felony alloc entry is not an object"))?;
        let storage = entry
            .entry("storage")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| eyre!("felony storage is not an object"))?;
        let thr = json!(format!("0x{DEV_FELONY_THRESHOLD:064x}"));
        storage.insert(format!("0x{:064x}", 1u64), thr.clone());
        storage.insert(format!("0x{:064x}", 13u64), thr);

        fs::write(&path, serde_json::to_string_pretty(&g)? + "\n")?;
        Ok(())
    }
}

/// A `TESTNET_*` tuning override parsed as `u64`, or `default`.
fn tuned(tuning: &[(&str, String)], key: &str, default: u64) -> u64 {
    tuning
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(default)
}

/// Whether an alloc key normalizes (lowercase, `0x`-stripped, left-padded to 40)
/// to a SlashIndicator address ending in `ee01` (`bootstrap-testnet.sh:244`).
fn ends_with_ee01(key: &str) -> bool {
    let k = key.to_lowercase();
    let k = k.strip_prefix("0x").unwrap_or(&k);
    format!("{k:0>40}").ends_with("ee01")
}
