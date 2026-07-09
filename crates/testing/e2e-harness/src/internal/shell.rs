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
    ///
    /// A non-zero exit is **not** an error — callers parse stdout and several
    /// treat an empty result as "not available". But it is always reported, with
    /// the command and both streams, so a failing send is never silent. (It used
    /// to discard stderr unless `--debug`, which left the caller failing later
    /// with no trace of why.)
    pub fn cli<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let sh = self.shell()?;
        // Collected so the same argv can be both passed and logged.
        let argv: Vec<String> = args
            .into_iter()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .collect();
        let out = sh
            .cmd(&self.cfg.bin_cli)
            .args(&argv)
            .env("PATH", &self.cfg.path)
            .quiet()
            .ignore_status()
            .output()?;

        // `Cmd::read` strips one trailing newline; `Cmd::output` doesn't. Callers
        // parse this stdout, so keep the old shape.
        let mut stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if stdout.ends_with('\n') {
            stdout.pop();
            if stdout.ends_with('\r') {
                stdout.pop();
            }
        }

        let cmdline = format!("{} {}", self.cfg.bin_cli.display(), argv.join(" "));
        if !out.status.success() {
            eprintln!(
                "[cli] FAILED {cmdline}\n      exit: {}\n      stdout: {}\n      stderr: {}",
                out.status,
                stdout.trim(),
                String::from_utf8_lossy(&out.stderr).trim(),
            );
        } else if self.cfg.debug {
            eprintln!("[cli] {cmdline}");
        }
        Ok(stdout)
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
