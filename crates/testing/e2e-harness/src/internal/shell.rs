//! Thin `xshell` wrapper for the two subprocess surfaces the harness still uses:
//! `outbe-cli` sends (the product CLI under test) and best-effort `sudo`
//! cleanup (`pkill`/`docker rm`). Node/enclave launches and the localnet
//! lifecycle are owned Rust processes (see `world::localnet` / `internal::proc`).

use std::ffi::OsStr;

use eyre::Result;
use xshell::Shell;

use super::config::Config;

pub(crate) struct Sh<'a> {
    cfg: &'a Config,
}

impl<'a> Sh<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        Self { cfg }
    }

    fn shell(&self) -> Result<Shell> {
        let sh = Shell::new()?;
        sh.change_dir(&self.cfg.repo);
        Ok(sh)
    }

    /// Run `outbe-cli <args>` (caller supplies global `--rpc-url` / `--private-key`)
    /// and capture stdout.
    pub fn cli<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let sh = self.shell()?;
        let mut cmd = sh
            .cmd(&self.cfg.bin_cli)
            .args(args)
            .env("PATH", &self.cfg.path)
            .quiet()
            .ignore_status();
        if !self.cfg.debug {
            cmd = cmd.ignore_stderr();
        }
        let out = cmd.read()?;
        Ok(out)
    }

    /// Run a raw command (program + args) under `sudo` unless `E2E_NO_SUDO`,
    /// ignoring failure. Used for best-effort cleanup (pkill/docker rm).
    pub fn sudo_best_effort(&self, program: &str, args: &[&str]) {
        let Ok(sh) = self.shell() else { return };
        let cmd = if !self.cfg.sudo {
            sh.cmd(program).args(args.iter().copied())
        } else {
            let mut parts = vec![program.to_string()];
            parts.extend(args.iter().map(|s| s.to_string()));
            sh.cmd("sudo").args(parts)
        }
        .env("PATH", &self.cfg.path)
        .ignore_status();

        if self.cfg.debug {
            let _ = cmd.run();
        } else {
            let _ = cmd.output();
        }
    }
}
