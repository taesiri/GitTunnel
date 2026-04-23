use std::fs;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::crypto::TunnelCipher;
use crate::frame::{safe_component, Direction, Frame, StoredFrame};
use crate::git_branch::GitBranch;
use crate::ssh;

pub const DEFAULT_MAX_BLOB_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct GitRelay {
    inner: Arc<Inner>,
}

struct Inner {
    repo_url: String,
    branches: BranchSet,
    write_direction: Option<Direction>,
    session_id: String,
    workdir: PathBuf,
    owns_workdir: bool,
    cipher: Option<TunnelCipher>,
    min_push_interval: Duration,
    poll_interval: Duration,
    trace_frames: bool,
    defer_cleanup: bool,
    max_blob_bytes: usize,
    /// Value for `GIT_SSH_COMMAND` that enables SSH ControlMaster multiplexing.
    /// `None` for non-SSH remotes (file://, https://).
    ssh_env: Option<String>,
    client_to_exit_branch: Arc<GitBranch>,
    exit_to_client_branch: Arc<GitBranch>,
    base_branch: Arc<GitBranch>,
}

#[derive(Debug, Clone)]
struct BranchSet {
    base: String,
    client_to_exit: String,
    exit_to_client: String,
    include_legacy_for_clean: bool,
}

#[derive(Debug, Clone)]
pub struct WriteStats {
    pub branch: String,
    pub frame_count: usize,
    pub payload_bytes: usize,
    pub encoded_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct RelayTuning {
    pub min_push_interval: Duration,
    pub poll_interval: Duration,
    pub trace_frames: bool,
    pub defer_cleanup: bool,
    pub max_blob_bytes: usize,
}

impl RelayTuning {
    pub fn new(
        min_push_interval: Duration,
        poll_interval: Duration,
        trace_frames: bool,
        defer_cleanup: bool,
        max_blob_bytes: usize,
    ) -> Self {
        Self {
            min_push_interval,
            poll_interval,
            trace_frames,
            defer_cleanup,
            max_blob_bytes,
        }
    }
}

impl BranchSet {
    fn single(branch: String) -> Self {
        Self {
            base: branch.clone(),
            client_to_exit: branch.clone(),
            exit_to_client: branch,
            include_legacy_for_clean: false,
        }
    }

    fn split(base: String) -> Self {
        Self {
            client_to_exit: format!("{base}/c2e"),
            exit_to_client: format!("{base}/e2c"),
            base,
            include_legacy_for_clean: false,
        }
    }

    fn clean_targets(base: String) -> Self {
        Self {
            client_to_exit: format!("{base}/c2e"),
            exit_to_client: format!("{base}/e2c"),
            base,
            include_legacy_for_clean: true,
        }
    }

    fn branch_for_direction(&self, direction: Direction) -> &str {
        match direction {
            Direction::ClientToExit => &self.client_to_exit,
            Direction::ExitToClient => &self.exit_to_client,
        }
    }

    fn primary(&self) -> &str {
        &self.client_to_exit
    }

    fn is_split(&self) -> bool {
        self.client_to_exit != self.exit_to_client
    }

    fn branches_for_read(&self, direction: Option<Direction>) -> Vec<&str> {
        match direction {
            Some(direction) => vec![self.branch_for_direction(direction)],
            None if self.is_split() => vec![&self.client_to_exit, &self.exit_to_client],
            None => vec![self.primary()],
        }
    }

    fn branches_for_clean(&self) -> Vec<&str> {
        let mut branches = vec![self.client_to_exit.as_str(), self.exit_to_client.as_str()];
        if self.include_legacy_for_clean || !self.is_split() {
            branches.push(self.base.as_str());
        }
        branches.sort_unstable();
        branches.dedup();
        branches
    }
}

impl GitRelay {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo_url: String,
        branch: String,
        session_id: String,
        workdir: Option<PathBuf>,
        cipher: TunnelCipher,
        min_push_interval: Duration,
        poll_interval: Duration,
        trace_frames: bool,
    ) -> Result<Self> {
        Self::build(
            repo_url,
            BranchSet::single(branch),
            None,
            session_id,
            workdir,
            Some(cipher),
            RelayTuning::new(
                min_push_interval,
                poll_interval,
                trace_frames,
                false,
                DEFAULT_MAX_BLOB_BYTES,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_split(
        repo_url: String,
        branch_base: String,
        write_direction: Direction,
        session_id: String,
        workdir: Option<PathBuf>,
        cipher: TunnelCipher,
        tuning: RelayTuning,
    ) -> Result<Self> {
        Self::build(
            repo_url,
            BranchSet::split(branch_base),
            Some(write_direction),
            session_id,
            workdir,
            Some(cipher),
            tuning,
        )
    }

    pub fn without_cipher(
        repo_url: String,
        branch: String,
        workdir: Option<PathBuf>,
        min_push_interval: Duration,
        poll_interval: Duration,
        trace_frames: bool,
    ) -> Result<Self> {
        let session_id = Self::session_from_branch(&branch);
        Self::build(
            repo_url,
            BranchSet::clean_targets(branch),
            None,
            session_id,
            workdir,
            None,
            RelayTuning::new(
                min_push_interval,
                poll_interval,
                trace_frames,
                false,
                DEFAULT_MAX_BLOB_BYTES,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        repo_url: String,
        branches: BranchSet,
        write_direction: Option<Direction>,
        session_id: String,
        workdir: Option<PathBuf>,
        cipher: Option<TunnelCipher>,
        tuning: RelayTuning,
    ) -> Result<Self> {
        if branches.base.trim().is_empty() {
            bail!("branch must not be empty");
        }
        let owns_workdir = workdir.is_none();
        let workdir_key = write_direction
            .map(|direction| format!("{}:{}", branches.base, direction.as_path()))
            .unwrap_or_else(|| branches.primary().to_string());
        let workdir = workdir.unwrap_or_else(|| default_workdir(&repo_url, &workdir_key));
        let ssh_env = if ssh::is_ssh_remote(&repo_url) {
            Some(ssh::ssh_env_for_control_dir(&ssh::control_dir()))
        } else {
            None
        };
        let client_to_exit_branch = git_branch_for(
            &repo_url,
            &branches.client_to_exit,
            &workdir,
            &ssh_env,
            &cipher,
            tuning,
        );
        let exit_to_client_branch = if branches.exit_to_client == branches.client_to_exit {
            client_to_exit_branch.clone()
        } else {
            git_branch_for(
                &repo_url,
                &branches.exit_to_client,
                &workdir,
                &ssh_env,
                &cipher,
                tuning,
            )
        };
        let base_branch = if branches.base == branches.client_to_exit {
            client_to_exit_branch.clone()
        } else if branches.base == branches.exit_to_client {
            exit_to_client_branch.clone()
        } else {
            git_branch_for(
                &repo_url,
                &branches.base,
                &workdir,
                &ssh_env,
                &cipher,
                tuning,
            )
        };
        Ok(Self {
            inner: Arc::new(Inner {
                repo_url,
                branches,
                write_direction,
                session_id,
                workdir,
                owns_workdir,
                cipher,
                min_push_interval: tuning.min_push_interval,
                poll_interval: tuning.poll_interval,
                trace_frames: tuning.trace_frames,
                defer_cleanup: tuning.defer_cleanup,
                max_blob_bytes: tuning.max_blob_bytes,
                ssh_env,
                client_to_exit_branch,
                exit_to_client_branch,
                base_branch,
            }),
        })
    }

    pub fn session_from_branch(branch: &str) -> String {
        let safe = safe_component(branch);
        if safe.is_empty() {
            "default".to_string()
        } else {
            safe
        }
    }

    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn poll_interval(&self) -> Duration {
        self.inner.poll_interval
    }

    pub async fn ensure_ready(&self) -> Result<()> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.ensure_ready_blocking())
            .await
            .context("relay setup task failed")?
    }

    pub async fn write_frame(&self, frame: Frame) -> Result<WriteStats> {
        self.write_frames(vec![frame]).await
    }

    pub async fn write_frames(&self, frames: Vec<Frame>) -> Result<WriteStats> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.write_frames_blocking(frames))
            .await
            .context("relay write task failed")?
    }

    pub async fn read_frames(&self, direction: Option<Direction>) -> Result<Vec<StoredFrame>> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.read_frames_blocking(direction))
            .await
            .context("relay read task failed")?
    }

    pub async fn cleanup_acked(&self) -> Result<usize> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.cleanup_acked_blocking())
            .await
            .context("relay cleanup task failed")?
    }

    pub async fn clean(&self) -> Result<()> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.clean_blocking())
            .await
            .context("relay clean task failed")?
    }
}

impl Inner {
    fn ensure_ready_blocking(&self) -> Result<()> {
        let branch = self
            .write_direction
            .map(|direction| self.branches.branch_for_direction(direction))
            .unwrap_or_else(|| self.branches.primary());
        self.branch_for_name(branch).ensure_ready()
    }

    fn write_frames_blocking(&self, frames: Vec<Frame>) -> Result<WriteStats> {
        let first = frames
            .first()
            .ok_or_else(|| anyhow::anyhow!("frame batch must not be empty"))?;
        let direction = first.header.direction;
        if let Some(write_direction) = self.write_direction {
            if direction != write_direction {
                bail!(
                    "relay is configured as single-writer for {:?}, got {:?}",
                    write_direction,
                    direction
                );
            }
        }
        let branch = self.branches.branch_for_direction(direction);
        self.branch_for_name(branch).write_frames(frames)
    }

    fn read_frames_blocking(&self, direction: Option<Direction>) -> Result<Vec<StoredFrame>> {
        let mut frames = Vec::new();
        for branch in self.branches.branches_for_read(direction) {
            frames.extend(
                self.branch_for_name(branch)
                    .read_frames()?
                    .into_iter()
                    .filter(|stored| {
                        direction.is_none_or(|wanted| stored.frame.header.direction == wanted)
                    }),
            );
        }
        frames.sort_by_key(|stored| {
            (
                stored.frame.header.stream_id,
                stored.frame.header.seq,
                stored.frame.header.direction.as_path(),
            )
        });
        Ok(frames)
    }

    fn cleanup_acked_blocking(&self) -> Result<usize> {
        if self.defer_cleanup {
            debug!("cleanup skipped because deferred cleanup is enabled");
            return Ok(0);
        }
        if self.branches.is_split() {
            debug!("cleanup skipped for split branches; run clean after the demo");
            return Ok(0);
        }
        let branch = self.branch_for_name(self.branches.primary());
        let frames = branch.read_frames()?;
        branch.cleanup_acked(&frames)
    }

    fn clean_blocking(&self) -> Result<()> {
        for branch in self.branches.branches_for_clean() {
            self.branch_for_name(branch).delete_remote()?;
        }

        if self.owns_workdir && self.workdir.exists() {
            fs::remove_dir_all(&self.workdir)
                .with_context(|| format!("failed to remove {}", self.workdir.display()))?;
            info!(workdir = %self.workdir.display(), "removed relay cache");
        } else {
            info!(workdir = %self.workdir.display(), "left custom relay workdir in place");
        }
        Ok(())
    }

    fn branch_for_name(&self, branch: &str) -> Arc<GitBranch> {
        if branch == self.branches.client_to_exit {
            self.client_to_exit_branch.clone()
        } else if branch == self.branches.exit_to_client {
            self.exit_to_client_branch.clone()
        } else if branch == self.branches.base {
            self.base_branch.clone()
        } else {
            git_branch_for(
                &self.repo_url,
                branch,
                &self.workdir,
                &self.ssh_env,
                &self.cipher,
                RelayTuning::new(
                    self.min_push_interval,
                    self.poll_interval,
                    self.trace_frames,
                    self.defer_cleanup,
                    self.max_blob_bytes,
                ),
            )
        }
    }
}

fn git_branch_for(
    repo_url: &str,
    branch_name: &str,
    workdir: &Path,
    ssh_env: &Option<String>,
    cipher: &Option<TunnelCipher>,
    tuning: RelayTuning,
) -> Arc<GitBranch> {
    Arc::new(GitBranch::new(
        repo_url.to_string(),
        branch_name.to_string(),
        workdir.join(safe_component(branch_name)),
        ssh_env.clone(),
        tuning.min_push_interval,
        tuning.max_blob_bytes,
        tuning.trace_frames,
        tuning.defer_cleanup,
        cipher.clone(),
    ))
}

fn default_workdir(repo_url: &str, branch: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(repo_url.as_bytes());
    hasher.update(b"\0");
    hasher.update(branch.as_bytes());
    let hash = hex::encode(hasher.finalize());
    std::env::temp_dir().join("gittunnel").join(&hash[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Direction, FramePayload};
    use tempfile::TempDir;

    #[tokio::test]
    async fn writes_and_reads_frames_through_local_bare_repo() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();

        let relay = GitRelay::new(
            bare.to_string_lossy().to_string(),
            "git-tunnel/test".to_string(),
            "session".to_string(),
            Some(temp.path().join("work")),
            TunnelCipher::from_key_bytes([1; 32]),
            Duration::from_millis(0),
            Duration::from_millis(10),
            false,
        )
        .unwrap();
        relay.ensure_ready().await.unwrap();

        let frame = Frame::new(
            "session",
            1,
            Direction::ClientToExit,
            1,
            0,
            FramePayload::data(b"hello"),
        );
        relay.write_frame(frame).await.unwrap();

        let frames = relay
            .read_frames(Some(Direction::ClientToExit))
            .await
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame.payload.data_bytes().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn split_branches_route_directions_and_enforce_single_writer() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();

        let tuning = RelayTuning::new(
            Duration::from_millis(0),
            Duration::from_millis(10),
            false,
            true,
            DEFAULT_MAX_BLOB_BYTES,
        );
        let client = GitRelay::new_split(
            bare.to_string_lossy().to_string(),
            "git-tunnel/split".to_string(),
            Direction::ClientToExit,
            "session".to_string(),
            Some(temp.path().join("client-work")),
            TunnelCipher::from_key_bytes([2; 32]),
            tuning,
        )
        .unwrap();
        let exit = GitRelay::new_split(
            bare.to_string_lossy().to_string(),
            "git-tunnel/split".to_string(),
            Direction::ExitToClient,
            "session".to_string(),
            Some(temp.path().join("exit-work")),
            TunnelCipher::from_key_bytes([2; 32]),
            tuning,
        )
        .unwrap();
        client.ensure_ready().await.unwrap();
        exit.ensure_ready().await.unwrap();

        client
            .write_frame(Frame::new(
                "session",
                1,
                Direction::ClientToExit,
                1,
                0,
                FramePayload::data(b"split"),
            ))
            .await
            .unwrap();

        let frames = exit
            .read_frames(Some(Direction::ClientToExit))
            .await
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame.payload.data_bytes().unwrap(), b"split");

        let wrong_direction = client
            .write_frame(Frame::new(
                "session",
                1,
                Direction::ExitToClient,
                1,
                0,
                FramePayload::data(b"wrong"),
            ))
            .await;
        assert!(wrong_direction.is_err());

        let refs = Command::new("git")
            .args(["show-ref"])
            .current_dir(&bare)
            .output()
            .unwrap();
        let refs = String::from_utf8_lossy(&refs.stdout);
        assert!(refs.contains("refs/heads/git-tunnel/split/c2e"));
        assert!(refs.contains("refs/heads/git-tunnel/split/e2c"));
    }
}
