//! Node-state probes: datadir moves and node-log inspection used by the
//! recovery/promotion scenarios.

use std::fs;

use eyre::{Result, WrapErr};

use crate::internal::shell::Sh;

use super::Localnet;

impl Localnet {
    /// Relocate a datadir under the data dir (warm promotion reuses synced state).
    pub fn move_datadir(&self, from_rel: &str, to_rel: &str) -> Result<()> {
        let from = self.cfg.dir.join(from_rel);
        let to = self.cfg.dir.join(to_rel);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::rename(&from, &to) {
            Ok(()) => Ok(()),
            Err(_) if self.cfg.sudo => {
                Sh::new(&self.cfg).sudo_best_effort(
                    "mv",
                    &[&from.display().to_string(), &to.display().to_string()],
                );
                Ok(())
            }
            Err(e) => Err(e).wrap_err("move datadir"),
        }
    }

    fn node_log(&self, node: &str) -> String {
        let path = self.cfg.dir.join(node).join("node.log");
        fs::read_to_string(path).unwrap_or_default()
    }

    /// Whether validator `index`'s owned node process has already exited.
    pub fn validator_exited(&mut self, index: usize) -> bool {
        match self.validators.get_mut(&index) {
            Some(guard) => guard.exited(),
            None => true,
        }
    }

    /// Whether validator `index`'s log contains `needle` (`e2e_joiner_log_has`).
    pub fn log_has(&self, index: usize, needle: &str) -> bool {
        self.node_log(&format!("validator-{index}")).contains(needle)
    }

    /// Count of log LINES containing `needle` (matches shell `grep -c`).
    pub fn log_count(&self, index: usize, needle: &str) -> usize {
        self.node_log(&format!("validator-{index}"))
            .lines()
            .filter(|l| l.contains(needle))
            .count()
    }

    /// The `--consensus.keys-dir` for validator `index` (persisted-share restart).
    pub fn keys_dir(&self, index: usize) -> String {
        self.cfg
            .validator_dir(index)
            .join("keys")
            .display()
            .to_string()
    }

    /// Whether a durable DKG share file exists in validator `index`'s keys dir
    /// (`e2e_assert "DKG share persisted to keys-dir"`, s4:28-29).
    pub fn has_share_file(&self, index: usize) -> bool {
        let dir = self.cfg.validator_dir(index).join("keys");
        fs::read_dir(&dir)
            .map(|rd| {
                rd.filter_map(Result::ok).any(|e| {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    (n.contains("dkg") && n.contains("share")) || n == "dkg_share.hex"
                })
            })
            .unwrap_or(false)
    }
}
