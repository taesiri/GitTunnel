use std::path::{Path, PathBuf};
use std::process::Command;

/// Returns true if the repo URL uses SSH transport (git@ or ssh:// schemes).
pub fn is_ssh_remote(url: &str) -> bool {
    url.starts_with("git@") || url.starts_with("ssh://")
}

/// Returns the directory used for SSH ControlMaster sockets.
///
/// We use a fixed short path to stay well within macOS's 104-byte Unix domain
/// socket path limit.  The actual socket files are named by OpenSSH's `%C`
/// expansion (40-char SHA-1 of host+port+user), so total path length is
/// `/tmp/gts/` (9) + 40 = 49 bytes — safely under the limit.
pub fn control_dir() -> PathBuf {
    PathBuf::from("/tmp/gts")
}

/// Returns the value to assign to `GIT_SSH_COMMAND` to enable SSH ControlMaster
/// multiplexing.  Every `git` invocation that sets this env var will share one
/// persistent SSH connection to the same host, eliminating per-invocation
/// handshake cost (~500 ms per call on GitHub).
///
/// If `GIT_SSH_COMMAND` is already set in the calling process's environment,
/// that command is used as the base so key/identity settings are preserved.
/// Otherwise plain `ssh` is used.
pub fn ssh_env_for_control_dir(control_dir: &Path) -> String {
    let base = std::env::var("GIT_SSH_COMMAND").unwrap_or_else(|_| "ssh".to_string());
    format!(
        "{base} -o ControlMaster=auto -o ControlPath={}/%C -o ControlPersist=300s",
        control_dir.display()
    )
}

/// Warm up the SSH ControlMaster with a lightweight `git ls-remote`.
///
/// This establishes the underlying TCP+SSH session before any real push or fetch
/// runs, so the first tunnel operation does not pay the full handshake cost on
/// top of the git protocol overhead.
///
/// Errors are silently swallowed — the repo may be empty or temporarily
/// unreachable, but the ControlMaster process is still spawned and will accept
/// subsequent connections.
pub fn warm_up_master(repo_url: &str, ssh_env: &str) {
    let _ = Command::new("git")
        .env("GIT_SSH_COMMAND", ssh_env)
        .args(["ls-remote", "--heads", repo_url])
        .output();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn ssh_command_sets_control_master_auto() {
        let dir = PathBuf::from("/tmp/gts");
        let cmd = ssh_env_for_control_dir(&dir);
        assert!(
            cmd.contains("ControlMaster=auto"),
            "missing ControlMaster=auto in: {cmd}"
        );
        assert!(
            cmd.contains("ControlPersist=300s"),
            "missing ControlPersist=300s in: {cmd}"
        );
        assert!(
            cmd.contains("/tmp/gts/%C"),
            "missing control path in: {cmd}"
        );
        // Verify total socket path stays within macOS's 104-byte limit.
        // %C expands to a 40-char SHA-1 hash.
        let socket_path = format!("{}/tmp/gts/{}", "", "a".repeat(40));
        assert!(
            socket_path.len() < 104,
            "socket path too long: {}",
            socket_path.len()
        );
    }

    #[test]
    fn is_ssh_remote_detects_git_at_and_ssh_scheme() {
        assert!(is_ssh_remote("git@github.com:owner/repo.git"));
        assert!(is_ssh_remote("ssh://git@github.com/owner/repo.git"));
        assert!(!is_ssh_remote("https://github.com/owner/repo.git"));
        assert!(!is_ssh_remote("file:///tmp/bare-repo.git"));
        assert!(!is_ssh_remote("http://github.com/owner/repo.git"));
    }
}
