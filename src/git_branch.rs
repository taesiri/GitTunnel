use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

use crate::crypto::TunnelCipher;
use crate::frame::{acked_frame_paths, Frame, FrameBatch, StoredFrame};
use crate::git_relay::WriteStats;
use crate::ssh;

const REMOTE: &str = "origin";
const CACHE_MARKER: &str = "gittunnel-cache";

pub struct GitBranch {
    repo_url: String,
    branch_name: String,
    workdir: PathBuf,
    ssh_env: Option<String>,
    min_push_interval: Duration,
    max_blob_bytes: usize,
    trace_frames: bool,
    defer_cleanup: bool,
    cipher: Option<TunnelCipher>,
    state: Mutex<BranchState>,
}

#[derive(Debug, Default)]
struct BranchState {
    last_push: Option<Instant>,
}

impl GitBranch {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repo_url: String,
        branch_name: String,
        workdir: PathBuf,
        ssh_env: Option<String>,
        min_push_interval: Duration,
        max_blob_bytes: usize,
        trace_frames: bool,
        defer_cleanup: bool,
        cipher: Option<TunnelCipher>,
    ) -> Self {
        Self {
            repo_url,
            branch_name,
            workdir,
            ssh_env,
            min_push_interval,
            max_blob_bytes,
            trace_frames,
            defer_cleanup,
            cipher,
            state: Mutex::new(BranchState::default()),
        }
    }

    pub(crate) fn ensure_ready(&self) -> Result<()> {
        let _guard = self.state.lock().expect("branch mutex poisoned");
        self.ensure_ready_locked()
    }

    fn ensure_ready_locked(&self) -> Result<()> {
        fs::create_dir_all(&self.workdir).with_context(|| {
            format!("failed to create relay workdir {}", self.workdir.display())
        })?;
        self.prepare_ssh()?;
        self.write_cache_marker()?;

        if !self.workdir.join(".git").exists() {
            self.git_init()?;
        }
        self.git(["remote", "remove", REMOTE]).ok();
        self.git(["remote", "add", REMOTE, self.repo_url.as_str()])?;
        self.configure_git()?;

        self.sync_to_remote_or_create_locked()
    }

    pub fn write_frames(&self, frames: Vec<Frame>) -> Result<WriteStats> {
        let mut state = self.state.lock().expect("branch mutex poisoned");
        let cipher = self.cipher()?;
        let first = frames
            .first()
            .ok_or_else(|| anyhow::anyhow!("frame batch must not be empty"))?;
        let relative_path = FrameBatch::relative_path(&frames)?;
        let payload_bytes = FrameBatch::payload_bytes(&frames)?;
        let encoded = FrameBatch::encode(&frames, cipher)?;
        if encoded.len() > self.max_blob_bytes {
            bail!(
                "encoded frame batch is {} bytes, above configured blob cap {} bytes",
                encoded.len(),
                self.max_blob_bytes
            );
        }

        for attempt in 0..5 {
            self.sync_to_remote_or_create_locked()?;
            let path = self.workdir.join(&relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::write(&path, &encoded)
                .with_context(|| format!("failed to write frame {}", path.display()))?;
            self.git(["add", path_arg(&relative_path).as_str()])?;

            let commit = self.git_status([
                "commit",
                "-m",
                &format!(
                    "gittunnel batch {} {}..{} ({} frames)",
                    first.header.direction.as_path(),
                    frames
                        .iter()
                        .map(|frame| frame.header.seq)
                        .min()
                        .unwrap_or(0),
                    frames
                        .iter()
                        .map(|frame| frame.header.seq)
                        .max()
                        .unwrap_or(0),
                    frames.len()
                ),
            ])?;
            if !commit.status.success() && !stderr_contains(&commit, "nothing to commit") {
                return Err(git_error("commit", &commit));
            }

            self.throttle_push(&mut state);
            let push = self.git_status([
                "push",
                REMOTE,
                &format!("HEAD:refs/heads/{}", self.branch_name),
            ])?;
            if push.status.success() {
                if self.trace_frames {
                    info!(
                        branch = self.branch_name.as_str(),
                        direction = first.header.direction.as_path(),
                        frames = frames.len(),
                        payload_bytes,
                        encoded_bytes = encoded.len(),
                        "pushed frame batch"
                    );
                }
                return Ok(WriteStats {
                    branch: self.branch_name.clone(),
                    frame_count: frames.len(),
                    payload_bytes,
                    encoded_bytes: encoded.len(),
                });
            }

            warn!(
                attempt = attempt + 1,
                stderr = %String::from_utf8_lossy(&push.stderr).trim(),
                "git push rejected; retrying after fetch"
            );
            thread::sleep(Duration::from_millis(500 * (1 << attempt)));
        }

        bail!("failed to push frame after retries")
    }

    pub fn read_frames(&self) -> Result<Vec<StoredFrame>> {
        let _guard = self.state.lock().expect("branch mutex poisoned");
        if !self.checkout_remote_branch_locked()? {
            return Ok(Vec::new());
        }
        self.read_frames_from_worktree()
    }

    pub fn cleanup_acked(&self, acked: &[StoredFrame]) -> Result<usize> {
        let mut state = self.state.lock().expect("branch mutex poisoned");
        if self.defer_cleanup {
            debug!("cleanup skipped because deferred cleanup is enabled");
            return Ok(0);
        }
        self.sync_to_remote_or_create_locked()?;
        let paths = acked_frame_paths(acked);
        if paths.is_empty() {
            return Ok(0);
        }

        let mut removed = 0;
        for relative_path in &paths {
            let path = self.workdir.join(relative_path);
            if path.exists() {
                fs::remove_file(&path)
                    .with_context(|| format!("failed to remove {}", path.display()))?;
                removed += 1;
            }
        }
        prune_empty_dirs(&self.workdir.join("frames"))?;
        self.compact_and_force_push_locked(&mut state)?;
        info!(removed, "compacted acknowledged relay frames");
        Ok(removed)
    }

    pub fn delete_remote(&self) -> Result<()> {
        let mut state = self.state.lock().expect("branch mutex poisoned");
        fs::create_dir_all(&self.workdir).with_context(|| {
            format!("failed to create relay workdir {}", self.workdir.display())
        })?;
        self.prepare_ssh()?;
        if !self.workdir.join(".git").exists() {
            self.git_init()?;
        }
        self.write_cache_marker()?;
        self.git(["remote", "remove", REMOTE]).ok();
        self.git(["remote", "add", REMOTE, self.repo_url.as_str()])?;
        self.configure_git()?;

        self.throttle_push(&mut state);
        let delete = self.git_status(["push", REMOTE, "--delete", self.branch_name.as_str()])?;
        if delete.status.success() {
            info!(branch = self.branch_name.as_str(), "deleted relay branch");
        } else if stderr_contains(&delete, "refusing to delete the current branch") {
            warn!(
                branch = self.branch_name.as_str(),
                "relay branch is the remote default/current branch; resetting it to an empty checkpoint"
            );
            self.reset_to_empty_checkpoint_locked(&mut state)?;
        } else {
            warn!(
                branch = self.branch_name.as_str(),
                stderr = %String::from_utf8_lossy(&delete.stderr).trim(),
                "relay branch delete failed or branch did not exist"
            );
        }
        Ok(())
    }

    pub fn reset_to_empty_checkpoint(&self) -> Result<()> {
        let mut state = self.state.lock().expect("branch mutex poisoned");
        fs::create_dir_all(&self.workdir).with_context(|| {
            format!("failed to create relay workdir {}", self.workdir.display())
        })?;
        self.prepare_ssh()?;
        if !self.workdir.join(".git").exists() {
            self.git_init()?;
        }
        self.write_cache_marker()?;
        self.git(["remote", "remove", REMOTE]).ok();
        self.git(["remote", "add", REMOTE, self.repo_url.as_str()])?;
        self.configure_git()?;
        self.reset_to_empty_checkpoint_locked(&mut state)
    }

    fn read_frames_from_worktree(&self) -> Result<Vec<StoredFrame>> {
        let cipher = self.cipher()?;
        let mut files = Vec::new();
        collect_relay_files(&self.workdir.join("frames"), &mut files)?;
        let mut frames = Vec::new();
        for path in files {
            let bytes = fs::read(&path)
                .with_context(|| format!("failed to read frame {}", path.display()))?;
            match FrameBatch::decode(cipher, &bytes) {
                Ok(decoded) => {
                    let relative_path = path
                        .strip_prefix(&self.workdir)
                        .unwrap_or(path.as_path())
                        .to_path_buf();
                    for frame in decoded {
                        if self.trace_frames {
                            debug!(
                                direction = frame.header.direction.as_path(),
                                stream_id = frame.header.stream_id,
                                seq = frame.header.seq,
                                flag = ?frame.header.flag,
                                path = %relative_path.display(),
                                "fetched frame"
                            );
                        }
                        frames.push(StoredFrame {
                            frame,
                            relative_path: relative_path.clone(),
                        });
                    }
                }
                Err(error) => warn!(path = %path.display(), %error, "skipping unreadable frame"),
            }
        }
        Ok(frames)
    }

    fn compact_and_force_push_locked(&self, state: &mut BranchState) -> Result<()> {
        self.git(["add", "-A"])?;
        let tree = self.git(["write-tree"])?;
        let commit = self.git_with_input(
            [
                "commit-tree",
                tree.trim(),
                "-m",
                "gittunnel compact acknowledged frames",
            ],
            "",
        )?;
        let commit = commit.trim();
        self.git(["reset", "--hard", commit])?;
        self.throttle_push(state);
        let push = self.git_status([
            "push",
            "--force-with-lease",
            REMOTE,
            &format!("{}:refs/heads/{}", commit, self.branch_name),
        ])?;
        if !push.status.success() {
            return Err(git_error("force push compacted branch", &push));
        }
        Ok(())
    }

    fn reset_to_empty_checkpoint_locked(&self, state: &mut BranchState) -> Result<()> {
        self.sync_to_remote_or_create_locked()?;
        self.clear_worktree()?;
        let marker_dir = self.workdir.join(".gittunnel");
        fs::create_dir_all(&marker_dir)?;
        fs::write(
            marker_dir.join("README.md"),
            "Scratch branch for GitTunnel relay frames.\n",
        )?;
        self.compact_and_force_push_locked(state)
    }

    fn sync_to_remote_or_create_locked(&self) -> Result<()> {
        self.ensure_ready_minimal()?;
        if self.checkout_remote_branch_locked()? {
            return Ok(());
        }

        self.create_initial_branch_locked()
    }

    fn checkout_remote_branch_locked(&self) -> Result<bool> {
        self.ensure_ready_minimal()?;
        if !self.fetch_branch()?.status.success() {
            return Ok(false);
        }
        self.git([
            "checkout",
            "-B",
            self.branch_name.as_str(),
            &format!("refs/remotes/{}/{}", REMOTE, self.branch_name),
        ])?;
        self.git([
            "reset",
            "--hard",
            &format!("refs/remotes/{}/{}", REMOTE, self.branch_name),
        ])?;
        Ok(true)
    }

    fn ensure_ready_minimal(&self) -> Result<()> {
        fs::create_dir_all(&self.workdir).with_context(|| {
            format!("failed to create relay workdir {}", self.workdir.display())
        })?;
        self.write_cache_marker()?;
        if !self.workdir.join(".git").exists() {
            self.git_init()?;
            self.git(["remote", "add", REMOTE, self.repo_url.as_str()])?;
            self.configure_git()?;
        }
        Ok(())
    }

    fn create_initial_branch_locked(&self) -> Result<()> {
        self.clear_worktree()?;
        let checkout = self.git_status(["checkout", "--orphan", self.branch_name.as_str()])?;
        if !checkout.status.success() {
            self.git(["checkout", "-B", self.branch_name.as_str()])?;
        }
        self.git(["rm", "-r", "--cached", "."]).ok();
        self.clear_worktree()?;
        let marker_dir = self.workdir.join(".gittunnel");
        fs::create_dir_all(&marker_dir)?;
        fs::write(
            marker_dir.join("README.md"),
            "Scratch branch for GitTunnel relay frames.\n",
        )?;
        self.git(["add", ".gittunnel/README.md"])?;
        let commit = self.git_status(["commit", "-m", "gittunnel initialize relay branch"])?;
        if !commit.status.success() && !stderr_contains(&commit, "nothing to commit") {
            return Err(git_error("initial commit", &commit));
        }
        let push = self.git_status([
            "push",
            "-u",
            REMOTE,
            &format!("HEAD:refs/heads/{}", self.branch_name),
        ])?;
        if !push.status.success() {
            warn!(
                branch = self.branch_name.as_str(),
                stderr = %String::from_utf8_lossy(&push.stderr).trim(),
                "initial branch push failed; checking whether another peer created it"
            );
            if self.checkout_remote_branch_locked()? {
                return Ok(());
            }
            return Err(git_error("initial branch push", &push));
        }
        Ok(())
    }

    fn fetch_branch(&self) -> Result<Output> {
        self.git_status([
            "fetch",
            "--depth=1",
            REMOTE,
            &format!(
                "+refs/heads/{}:refs/remotes/{}/{}",
                self.branch_name, REMOTE, self.branch_name
            ),
        ])
    }

    fn clear_worktree(&self) -> Result<()> {
        if !self.workdir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.workdir)? {
            let entry = entry?;
            if entry.file_name() == OsStr::new(".git") {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    }

    fn prepare_ssh(&self) -> Result<()> {
        if let Some(ssh_env) = &self.ssh_env {
            let ssh_dir = ssh::control_dir();
            fs::create_dir_all(&ssh_dir).with_context(|| {
                format!("failed to create SSH control dir {}", ssh_dir.display())
            })?;
            ssh::warm_up_master(&self.repo_url, ssh_env);
        }
        Ok(())
    }

    fn write_cache_marker(&self) -> Result<()> {
        if self.workdir.join(".git").exists() {
            fs::write(self.workdir.join(".git").join(CACHE_MARKER), b"1")?;
        }
        Ok(())
    }

    fn configure_git(&self) -> Result<()> {
        self.git(["config", "user.email", "gittunnel@example.invalid"])?;
        self.git(["config", "user.name", "GitTunnel Demo"])?;
        self.git(["config", "advice.detachedHead", "false"])?;
        Ok(())
    }

    fn git_init(&self) -> Result<()> {
        fs::create_dir_all(&self.workdir)?;
        let output = self
            .git_command()
            .arg("init")
            .current_dir(&self.workdir)
            .output()
            .context("failed to run git init")?;
        if !output.status.success() {
            return Err(git_error("init", &output));
        }
        self.write_cache_marker()?;
        Ok(())
    }

    fn throttle_push(&self, state: &mut BranchState) {
        if let Some(last_push) = state.last_push {
            let elapsed = last_push.elapsed();
            if elapsed < self.min_push_interval {
                let sleep_for = self.min_push_interval - elapsed;
                debug!(millis = sleep_for.as_millis(), "throttling git push");
                thread::sleep(sleep_for);
            }
        }
        state.last_push = Some(Instant::now());
    }

    fn cipher(&self) -> Result<&TunnelCipher> {
        self.cipher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("relay operation requires an encryption key"))
    }

    /// Returns a `Command` for `git` pre-configured with `GIT_SSH_COMMAND` when
    /// the remote is an SSH URL. All git shell-outs must go through this helper
    /// so that SSH ControlMaster multiplexing is active on every invocation.
    fn git_command(&self) -> Command {
        let mut cmd = Command::new("git");
        if let Some(ssh_env) = &self.ssh_env {
            cmd.env("GIT_SSH_COMMAND", ssh_env);
        }
        cmd
    }

    fn git<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.git_status(args)?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        Err(git_error("git", &output))
    }

    fn git_with_input<I, S>(&self, args: I, input: &str) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = self
            .git_command()
            .args(args)
            .current_dir(&self.workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to run git")?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(input.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        Err(git_error("git", &output))
    }

    fn git_status<I, S>(&self, args: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.git_command()
            .args(args)
            .current_dir(&self.workdir)
            .output()
            .context("failed to run git")
    }
}

fn collect_relay_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_relay_files(&path, out)?;
        } else if matches!(
            path.extension().and_then(OsStr::to_str),
            Some("gtb" | "json")
        ) {
            out.push(path);
        }
    }
    Ok(())
}

fn prune_empty_dirs(root: &Path) -> Result<bool> {
    if !root.is_dir() {
        return Ok(false);
    }
    let mut empty = true;
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            if !prune_empty_dirs(&path)? {
                empty = false;
            }
        } else {
            empty = false;
        }
    }
    if empty {
        fs::remove_dir(root)?;
    }
    Ok(empty)
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn stderr_contains(output: &Output, needle: &str) -> bool {
    String::from_utf8_lossy(&output.stderr).contains(needle)
        || String::from_utf8_lossy(&output.stdout).contains(needle)
}

fn git_error(action: &str, output: &Output) -> anyhow::Error {
    anyhow::anyhow!(
        "git {} failed: {}{}",
        action,
        String::from_utf8_lossy(&output.stderr).trim(),
        if output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            String::new()
        }
    )
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use tempfile::TempDir;

    use crate::crypto::TunnelCipher;
    use crate::frame::{Direction, Frame, FramePayload};
    use crate::git_relay::{GitRelay, RelayTuning, DEFAULT_MAX_BLOB_BYTES};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_branches_push_in_parallel_without_index_lock() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let tuning = RelayTuning::new(
            Duration::from_millis(0),
            Duration::from_millis(10),
            false,
            true,
            DEFAULT_MAX_BLOB_BYTES,
        );
        let shared_workdir = temp.path().join("shared-work");
        let client = GitRelay::new_split(
            bare.to_string_lossy().to_string(),
            "git-tunnel/parallel".to_string(),
            Direction::ClientToExit,
            "session".to_string(),
            Some(shared_workdir.clone()),
            TunnelCipher::from_key_bytes([6; 32]),
            tuning,
        )
        .unwrap();
        let exit = GitRelay::new_split(
            bare.to_string_lossy().to_string(),
            "git-tunnel/parallel".to_string(),
            Direction::ExitToClient,
            "session".to_string(),
            Some(shared_workdir),
            TunnelCipher::from_key_bytes([6; 32]),
            tuning,
        )
        .unwrap();

        let (client_ready, exit_ready) = tokio::join!(client.ensure_ready(), exit.ensure_ready());
        client_ready.unwrap();
        exit_ready.unwrap();

        let client_write = client.write_frame(Frame::new(
            "session",
            1,
            Direction::ClientToExit,
            1,
            0,
            FramePayload::data(b"client"),
        ));
        let exit_write = exit.write_frame(Frame::new(
            "session",
            1,
            Direction::ExitToClient,
            1,
            0,
            FramePayload::data(b"exit"),
        ));
        let (client_result, exit_result) = tokio::join!(client_write, exit_write);
        if let Err(error) = client_result {
            panic!("client write failed: {error:#}");
        }
        if let Err(error) = exit_result {
            panic!("exit write failed: {error:#}");
        }

        let refs = Command::new("git")
            .args(["show-ref"])
            .current_dir(&bare)
            .output()
            .unwrap();
        assert!(refs.status.success());
        let refs = String::from_utf8_lossy(&refs.stdout);
        assert!(refs.contains("refs/heads/git-tunnel/parallel/c2e"));
        assert!(refs.contains("refs/heads/git-tunnel/parallel/e2c"));
    }
}
