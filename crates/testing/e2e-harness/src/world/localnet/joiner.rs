//! A validator that joins a running localnet: provision (keygen, fund, register,
//! enclave, `tee join`) and launch at index = committee size. Ported
//! `e2e_provision_joiner` / `e2e_launch_joiner`.

use std::fs;
use std::process::Command;

use alloy_primitives::{hex, Bytes};
use eyre::{eyre, Result};

use crate::internal::{
    addresses,
    eth::{self, IValidatorSet},
    proc::{
        self, args, attach_log, first_hex, random_hex_32, read_evm_key, read_trimmed, wait_tcp,
    },
    shell::Sh,
};

use super::Localnet;

impl Localnet {
    /// Provision a joiner: keygen, fund, register, p2p, enclave, `tee join`
    /// (port of `e2e_provision_joiner`). Leaves keys under `validator-<index>/`.
    pub fn provision_joiner(&mut self, index: usize) -> Result<()> {
        let vd = self.cfg.validator_dir(index);
        fs::create_dir_all(&vd)?;
        let signing_key = vd.join("signing-key.hex").display().to_string();

        // Fresh hybrid key material for the joiner.
        self.keygen(&["hybrid", "--output-dir", &vd.display().to_string()])?;
        let bls = first_hex(&self.keygen(&["show-pubkey", "--key", &signing_key])?, 96)
            .ok_or_else(|| eyre!("no BLS pubkey from keygen"))?;
        let key = read_evm_key(&vd)?;
        let addr = eth::address_of(&key).ok_or_else(|| eyre!("bad joiner evm key"))?;
        let sig = first_hex(
            &self.keygen(&[
                "sign-registration",
                "--key",
                &signing_key,
                "--validator-address",
                &format!("{addr:#x}"),
            ])?,
            120,
        )
        .ok_or_else(|| eyre!("no registration signature from keygen"))?;
        fs::write(vd.join("reth-p2p-secret.hex"), random_hex_32()?)?;

        // Fund from validator-0, register, and publish the p2p address.
        let v0 = read_evm_key(&self.cfg.validator_dir(0))?;
        eth::send_value(&self.cfg.rpc0, addr, &v0, eth::ether(2000))?;
        eth::send_call(
            &self.cfg.rpc0,
            addresses::VS_ADDR,
            &key,
            &IValidatorSet::registerValidatorCall {
                v: addr,
                pubkey: Bytes::from(hex::decode(&bls)?),
                sig: Bytes::from(hex::decode(&sig)?),
            },
            None,
        )?;
        eth::send_call(
            &self.cfg.rpc0,
            addresses::VS_ADDR,
            &key,
            &IValidatorSet::setP2pAddressCall {
                v: addr,
                kind: 1,
                addr: Bytes::from(hex::decode("00047f00000176c4")?),
            },
            None,
        )?;

        // Enclave container (owned foreground, no `-d`), then `tee join` once its
        // socket is up.
        let port = self.cfg.tee_port(index);
        proc::ensure_enclave_image(&self.cfg.repo, self.cfg.sudo)?;
        let guard = proc::spawn_enclave(proc::EnclaveSpec {
            name: self.cfg.tee_container(index),
            tee_port: port,
            enclave_bin: self.cfg.bin_mock.clone(),
            sudo: self.cfg.sudo,
            mock: true,
            dkg_seed: Some((index + 1).to_string()),
            seal: None,
            log_path: vd.join("enclave.log"),
            debug: self.cfg.debug,
        })?;
        self.enclaves.insert(index, guard);
        if !wait_tcp(port, 100) {
            return Err(eyre!("enclave socket 127.0.0.1:{port} never came up"));
        }
        let sock = format!("127.0.0.1:{port}");
        let _ = Sh::new(&self.cfg).cli([
            "tee",
            "join",
            "--enclave-socket",
            &sock,
            "--rpc-url",
            self.cfg.rpc0.as_str(),
            "--private-key",
            &key,
            "--timeout-secs",
            "60",
        ]);
        Ok(())
    }

    /// Launch the joiner node (validator-mode, verifier-join args), passing any
    /// extra node args (e.g. `--consensus.keys-dir ...`). Port of `e2e_launch_joiner`.
    pub fn launch_joiner(&mut self, index: usize, extra: &[&str]) -> Result<()> {
        let vd = self.cfg.validator_dir(index);
        fs::create_dir_all(vd.join("data"))?;
        fs::create_dir_all(vd.join("logs"))?;
        let secret = read_trimmed(&vd.join("reth-p2p-secret.hex"))?;

        let mut a = self.reth_base_args(&vd, index);
        a.extend(args![
            "--validator",
            "--bootnodes",
            self.bootnodes().unwrap_or_default(),
            "--p2p-secret-key-hex",
            secret,
            "--metrics",
            format!("0.0.0.0:{}", self.cfg.metrics_port(index)),
            "--consensus.signing-key",
            vd.join("signing-key.hex").display(),
            "--validator.evm-key",
            vd.join("evm-key.hex").display(),
            "--consensus.listen-addr",
            format!("127.0.0.1:{}", self.cfg.consensus_port(index)),
            "--consensus.peers",
            self.consensus_peers()?,
            "--consensus.use-local-defaults",
            "--tee-enclave-socket",
            format!("127.0.0.1:{}", self.cfg.tee_port(index)),
            "--consensus.public-polynomial",
            self.data_path("polynomial.hex"),
            "--consensus.dkg-output",
            self.data_path("dkg-output.hex"),
        ]);
        a.extend(extra.iter().map(|s| s.to_string()));

        let mut cmd = Command::new(&self.cfg.bin_chain);
        cmd.env("RUST_MIN_STACK", "16777216").args(&a);
        attach_log(&mut cmd, &vd)?;
        let guard = self.spawn_node(&format!("validator-{index}"), &vd, cmd)?;
        self.validators.insert(index, guard);
        Ok(())
    }

    /// Stop the joiner node (drop its owned handle → kill + reap). Port of
    /// `e2e_stop_joiner`.
    pub fn stop_joiner(&mut self, index: usize) -> Result<()> {
        self.validators.remove(&index);
        Ok(())
    }

    /// `--consensus.peers` (`<public_key>@<p2p_address>,…`) from `validators.json`.
    fn consensus_peers(&self) -> Result<String> {
        let raw = fs::read_to_string(self.cfg.dir.join("validators.json"))?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;
        let arr = v
            .as_array()
            .ok_or_else(|| eyre!("validators.json is not an array"))?;
        let peers: Vec<String> = arr
            .iter()
            .filter_map(|e| {
                let pk = e.get("public_key")?.as_str()?;
                let addr = e.get("p2p_address")?.as_str()?;
                Some(format!("{pk}@{addr}"))
            })
            .collect();
        Ok(peers.join(","))
    }

    /// Run `outbe-keygen <args>` and return stdout.
    fn keygen(&self, args: &[&str]) -> Result<String> {
        proc::run_capture(&self.cfg.bin_keygen, args)
    }
}
