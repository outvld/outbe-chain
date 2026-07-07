//! stdout/JSON parsers for `cast` and `outbe-cli` output.
//!
//! These replace the `sed -n '4p'` / `awk` / `jq` one-liners in
//! `scripts/e2e/lib.sh` and `update_operator_flow.sh` with small, testable
//! functions. No `regex` crate — the patterns are simple enough by hand.

/// Parse a value that may be decimal or `0x`-hex (uint values from `cast`).
pub(crate) fn hex_or_dec(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse().ok()
    }
}

/// Extract the first `0x…64hex` after "…ransaction sent:" — matches the bash
/// `extract_tx_hash` regex (`update_operator_flow.sh:141`). Works for both the
/// "Proposal transaction sent:" and "Vote transaction sent:" CLI lines.
pub(crate) fn extract_tx_hash(stdout: &str) -> Option<String> {
    const MARK: &str = "ransaction sent:";
    for line in stdout.lines() {
        let Some(pos) = line.find(MARK) else { continue };
        let rest = line[pos + MARK.len()..].trim_start();
        if let Some(body) = rest.strip_prefix("0x") {
            let hex: String = body.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() >= 64 {
                return Some(format!("0x{}", &hex[..64]));
            }
        }
    }
    None
}

/// A read-off of the `outbe-cli vote status` output.
#[derive(Debug, Default, Clone)]
pub struct VoteStatus {
    /// The `Proposal #<id>:` line was present.
    pub visible: bool,
    /// `status=` field (pending/approved/rejected/expired).
    pub status: String,
    /// `target=` field (module address, as printed).
    pub target: String,
    /// `deadline=` height.
    pub deadline: Option<u64>,
    /// yes tally from `votes=<yes>/<no>`.
    pub yes: u64,
    /// no tally from `votes=<yes>/<no>`.
    pub no: u64,
    /// The `payload:` line contents.
    pub payload: String,
}

/// Parse `outbe-cli vote status --proposal-id <id>` output for proposal `id`.
pub(crate) fn parse_vote_status(stdout: &str, id: u64) -> VoteStatus {
    let mut vs = VoteStatus {
        visible: stdout.contains(&format!("Proposal #{id}:")),
        ..Default::default()
    };
    let marker = format!("#{id}:");
    for line in stdout.lines() {
        if line.contains(&marker) {
            vs.target = field_after(line, "target=");
            vs.status = field_after(line, "status=");
            vs.deadline = hex_or_dec(&field_after(line, "deadline="));
            let votes = field_after(line, "votes=");
            if let Some((y, n)) = votes.split_once('/') {
                vs.yes = y.trim().parse().unwrap_or(0);
                vs.no = n.trim().parse().unwrap_or(0);
            }
        }
        if let Some(p) = line.trim().strip_prefix("payload:") {
            vs.payload = p.trim().to_string();
        }
    }
    vs
}

/// A read-off of `IUpdate.getScheduledUpdate` tuple fields.
#[derive(Debug, Clone)]
pub struct ScheduledUpdate {
    pub version: u64,
    pub activation: u64,
    /// 0 = waiting for activation, 1 = activated.
    pub status: u64,
}

/// `key=value` token from a space-separated status line; `value` runs to the
/// next whitespace.
fn field_after(line: &str, key: &str) -> String {
    match line.find(key) {
        Some(i) => line[i + key.len()..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_or_dec_both() {
        assert_eq!(hex_or_dec("65538"), Some(65538));
        assert_eq!(hex_or_dec("0x10002"), Some(65538));
        assert_eq!(hex_or_dec(" 0x0 "), Some(0));
    }

    #[test]
    fn tx_hash_from_cli_line() {
        let s = "Proposal transaction sent: 0xabc0000000000000000000000000000000000000000000000000000000000def (target 0x..)";
        assert_eq!(
            extract_tx_hash(s).as_deref(),
            Some("0xabc0000000000000000000000000000000000000000000000000000000000def")
        );
        assert_eq!(extract_tx_hash("nothing here"), None);
    }

    #[test]
    fn vote_status_line() {
        let out = "Proposal #1: target=0x000000000000000000000000000000000000EE0B status=pending deadline=100 votes=3/0\n  payload: {\"activationHeight\":1160}";
        let vs = parse_vote_status(out, 1);
        assert!(vs.visible);
        assert_eq!(vs.status, "pending");
        assert_eq!(vs.deadline, Some(100));
        assert_eq!((vs.yes, vs.no), (3, 0));
        assert!(vs.payload.contains("activationHeight"));
        assert!(vs.target.eq_ignore_ascii_case("0x000000000000000000000000000000000000EE0B"));
    }
}
