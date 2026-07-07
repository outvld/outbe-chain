//! Full-execution follower nodes (`--upstream`). Ported `launch_follower`.

use std::process::Command;
use std::fs;

use eyre::Result;

use crate::internal::proc::{args, attach_log, random_hex_32};

use super::Localnet;

impl Localnet {
    /// Launch a full-execution follower (`--upstream`). Ports derive from `slot`;
    /// the upstream URL and shared enclave derive from their slots.
    pub fn launch_follower(
        &mut self,
        name: &str,
        slot: usize,
        upstream_slot: usize,
        tee_slot: usize,
    ) -> Result<()> {
        let fd = self.cfg.dir.join(name);
        fs::create_dir_all(fd.join("data"))?;
        fs::create_dir_all(fd.join("logs"))?;

        let mut a = self.reth_base_args(&fd, slot);
        a.extend(args![
            "--p2p-secret-key-hex",
            random_hex_32()?,
            "--tee-enclave-socket",
            format!("127.0.0.1:{}", self.cfg.tee_port(tee_slot)),
            "--upstream",
            format!("http://localhost:{}", self.cfg.http_port(upstream_slot)),
        ]);

        let mut cmd = Command::new(&self.cfg.bin_chain);
        cmd.env("RUST_MIN_STACK", "16777216")
            .env("RUST_LOG", "info,outbe_consensus::follow=debug")
            .args(&a);
        attach_log(&mut cmd, &fd)?;
        let guard = self.spawn_node(name, &fd, cmd)?;
        self.followers.insert(name.to_string(), guard);
        Ok(())
    }

    /// Stop all follower nodes (drop owned handles → kill + reap).
    pub fn stop_followers(&mut self) -> Result<()> {
        self.followers.clear();
        Ok(())
    }
}
