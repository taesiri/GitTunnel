use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::crypto::TunnelCipher;
use crate::frame::{safe_component, Direction, Frame, FramePayload, StoredFrame};
use crate::git_branch::GitBranch;
use crate::git_relay::WriteStats;

pub const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(400);
pub const MAX_POLL_INTERVAL: Duration = Duration::from_millis(3_000);

pub struct StreamChannel {
    pub sid: u64,
    write_branch: Arc<GitBranch>,
    read_branch: Arc<GitBranch>,
    tx_seq: AtomicU64,
    state: Mutex<StreamState>,
    session_id: String,
    write_direction: Direction,
    read_direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Opening,
    Established,
    HalfClosedLocal,
    HalfClosedRemote,
    Closing,
    Closed,
}

impl StreamChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sid: u64,
        repo_url: &str,
        session_id: &str,
        write_dir: &str,
        read_dir: &str,
        ssh_env: Option<String>,
        cipher: Arc<TunnelCipher>,
        push_budget: usize,
    ) -> Result<Self> {
        let write_direction = direction_from_dir(write_dir)?;
        let read_direction = direction_from_dir(read_dir)?;
        let write_branch_name = stream_branch_name(session_id, sid, write_dir);
        let read_branch_name = stream_branch_name(session_id, sid, read_dir);
        let write_branch = Arc::new(GitBranch::new(
            repo_url.to_string(),
            write_branch_name.clone(),
            default_workdir(repo_url, &write_branch_name),
            ssh_env.clone(),
            Duration::from_millis(0),
            push_budget,
            false,
            true,
            Some((*cipher).clone()),
        ));
        let read_branch = Arc::new(GitBranch::new(
            repo_url.to_string(),
            read_branch_name.clone(),
            default_workdir(repo_url, &read_branch_name),
            ssh_env,
            Duration::from_millis(0),
            push_budget,
            false,
            true,
            Some((*cipher).clone()),
        ));

        Ok(Self {
            sid,
            write_branch,
            read_branch,
            tx_seq: AtomicU64::new(1),
            state: Mutex::new(StreamState::Opening),
            session_id: session_id.to_string(),
            write_direction,
            read_direction,
        })
    }

    pub async fn ensure_ready(&self) -> Result<()> {
        let write_branch = self.write_branch.clone();
        let read_branch = self.read_branch.clone();
        let (write_ready, read_ready) = tokio::join!(
            tokio::task::spawn_blocking(move || write_branch.ensure_ready()),
            tokio::task::spawn_blocking(move || read_branch.ensure_ready())
        );
        write_ready.context("stream write branch setup task failed")??;
        read_ready.context("stream read branch setup task failed")??;
        *self.state.lock().expect("stream mutex poisoned") = StreamState::Established;
        Ok(())
    }

    pub async fn write_frames(&self, frames: Vec<Frame>) -> Result<WriteStats> {
        self.validate_write_batch(&frames)?;
        let write_branch = self.write_branch.clone();
        tokio::task::spawn_blocking(move || write_branch.write_frames(frames))
            .await
            .context("stream write task failed")?
    }

    pub async fn read_frames(&self) -> Result<Vec<StoredFrame>> {
        let read_branch = self.read_branch.clone();
        let session_id = self.session_id.clone();
        let sid = self.sid;
        let read_direction = self.read_direction;
        let mut frames = tokio::task::spawn_blocking(move || read_branch.read_frames())
            .await
            .context("stream read task failed")??;
        frames.retain(|stored| {
            stored.frame.header.session_id == session_id
                && stored.frame.header.stream_id == sid
                && stored.frame.header.direction == read_direction
        });
        frames.sort_by_key(|stored| stored.frame.header.seq);
        Ok(frames)
    }

    pub async fn close(&self) -> Result<()> {
        {
            let mut state = self.state.lock().expect("stream mutex poisoned");
            if matches!(*state, StreamState::Closing | StreamState::Closed) {
                return Ok(());
            }
            *state = StreamState::Closing;
        }

        let half_close = self
            .write_frames(vec![self.next_frame(FramePayload::HalfClose)])
            .await;
        let write_branch = self.write_branch.clone();
        let delete = tokio::task::spawn_blocking(move || write_branch.delete_remote())
            .await
            .context("stream branch delete task failed")?;

        *self.state.lock().expect("stream mutex poisoned") = StreamState::Closed;
        half_close?;
        delete
    }

    pub async fn reset_for_reuse(&self) -> Result<()> {
        {
            let mut state = self.state.lock().expect("stream mutex poisoned");
            *state = StreamState::Closing;
        }

        let write_branch = self.write_branch.clone();
        let read_branch = self.read_branch.clone();
        let (write_reset, read_reset) = tokio::join!(
            tokio::task::spawn_blocking(move || write_branch.reset_to_empty_checkpoint()),
            tokio::task::spawn_blocking(move || read_branch.reset_to_empty_checkpoint())
        );
        write_reset.context("stream write branch reset task failed")??;
        read_reset.context("stream read branch reset task failed")??;
        self.tx_seq.store(1, Ordering::SeqCst);
        *self.state.lock().expect("stream mutex poisoned") = StreamState::Established;
        Ok(())
    }

    pub async fn delete_branches(&self) -> Result<()> {
        let write_branch = self.write_branch.clone();
        let read_branch = self.read_branch.clone();
        let (write_delete, read_delete) = tokio::join!(
            tokio::task::spawn_blocking(move || write_branch.delete_remote()),
            tokio::task::spawn_blocking(move || read_branch.delete_remote())
        );
        write_delete.context("stream write branch delete task failed")??;
        read_delete.context("stream read branch delete task failed")??;
        Ok(())
    }

    pub fn last_sent_seq(&self) -> u64 {
        self.tx_seq.load(Ordering::SeqCst).saturating_sub(1)
    }

    pub(crate) fn next_frame(&self, payload: FramePayload) -> Frame {
        Frame::new(
            self.session_id.clone(),
            self.sid,
            self.write_direction,
            self.tx_seq.fetch_add(1, Ordering::SeqCst),
            0,
            payload,
        )
    }

    pub(crate) fn mark_remote_half_closed(&self) {
        let mut state = self.state.lock().expect("stream mutex poisoned");
        if *state == StreamState::Established {
            *state = StreamState::HalfClosedRemote;
        }
    }

    fn validate_write_batch(&self, frames: &[Frame]) -> Result<()> {
        let first = frames
            .first()
            .ok_or_else(|| anyhow::anyhow!("frame batch must not be empty"))?;
        if first.header.stream_id != self.sid {
            bail!("stream write got frame for sid {}", first.header.stream_id);
        }
        if first.header.direction != self.write_direction {
            bail!(
                "stream write got {:?}, expected {:?}",
                first.header.direction,
                self.write_direction
            );
        }
        for frame in frames {
            if frame.header.stream_id != self.sid {
                bail!("stream write batch cannot mix streams");
            }
            if frame.header.direction != self.write_direction {
                bail!("stream write batch cannot mix directions");
            }
        }
        Ok(())
    }
}

pub fn stream_branch_name(session_id: &str, sid: u64, dir: &str) -> String {
    format!("gt/{}/s/{:016x}/{}", safe_component(session_id), sid, dir)
}

fn direction_from_dir(dir: &str) -> Result<Direction> {
    match dir {
        "c2e" => Ok(Direction::ClientToExit),
        "e2c" => Ok(Direction::ExitToClient),
        _ => bail!("stream direction must be c2e or e2c"),
    }
}

fn default_workdir(repo_url: &str, branch_name: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(repo_url.as_bytes());
    hasher.update(b"\0");
    hasher.update(branch_name.as_bytes());
    let hash = hex::encode(hasher.finalize());
    std::env::temp_dir()
        .join("gittunnel")
        .join("streams")
        .join(&hash[..16])
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;
    use crate::git_relay::DEFAULT_MAX_BLOB_BYTES;

    #[test]
    fn stream_branch_name_uses_hex_sid() {
        let branch = stream_branch_name("session", 1, "c2e");
        assert!(branch.contains("s/0000000000000001/c2e"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_streams_create_c2e_refs() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let cipher = Arc::new(TunnelCipher::from_key_bytes([10; 32]));
        let repo = bare.to_string_lossy().to_string();
        let stream1 = StreamChannel::new(
            1,
            &repo,
            "session",
            "c2e",
            "e2c",
            None,
            cipher.clone(),
            DEFAULT_MAX_BLOB_BYTES,
        )
        .unwrap();
        let stream2 = StreamChannel::new(
            2,
            &repo,
            "session",
            "c2e",
            "e2c",
            None,
            cipher,
            DEFAULT_MAX_BLOB_BYTES,
        )
        .unwrap();

        let (ready1, ready2) = tokio::join!(stream1.ensure_ready(), stream2.ensure_ready());
        ready1.unwrap();
        ready2.unwrap();

        let refs = Command::new("git")
            .args(["show-ref"])
            .current_dir(&bare)
            .output()
            .unwrap();
        assert!(refs.status.success());
        let refs = String::from_utf8_lossy(&refs.stdout);
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000001/c2e"));
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000002/c2e"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reset_for_reuse_clears_stale_frames() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let cipher = Arc::new(TunnelCipher::from_key_bytes([11; 32]));
        let repo = bare.to_string_lossy().to_string();
        let client = StreamChannel::new(
            1,
            &repo,
            "session",
            "c2e",
            "e2c",
            None,
            cipher.clone(),
            DEFAULT_MAX_BLOB_BYTES,
        )
        .unwrap();
        let exit = StreamChannel::new(
            1,
            &repo,
            "session",
            "e2c",
            "c2e",
            None,
            cipher,
            DEFAULT_MAX_BLOB_BYTES,
        )
        .unwrap();

        client.ensure_ready().await.unwrap();
        exit.ensure_ready().await.unwrap();
        client
            .write_frames(vec![client.next_frame(FramePayload::data(b"stale"))])
            .await
            .unwrap();
        assert_eq!(exit.read_frames().await.unwrap().len(), 1);

        client.reset_for_reuse().await.unwrap();

        assert!(exit.read_frames().await.unwrap().is_empty());
        assert_eq!(client.last_sent_seq(), 0);
    }
}
