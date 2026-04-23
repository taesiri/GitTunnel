use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::crypto::TunnelCipher;
use crate::frame::{safe_component, ControlPayload, Direction, Frame, FramePayload};
use crate::git_branch::GitBranch;
use crate::git_relay::{RelayTuning, DEFAULT_MAX_BLOB_BYTES};

pub type PushTuning = RelayTuning;

pub struct ControlChannel {
    relay: GitBranch,
    session_id: String,
    tx_seq: AtomicU64,
}

impl ControlChannel {
    pub fn new(
        repo_url: &str,
        session_id: &str,
        ssh_env: Option<String>,
        cipher: Arc<TunnelCipher>,
        tuning: PushTuning,
    ) -> Result<Self> {
        let branch = control_branch_name(session_id);
        Ok(Self {
            relay: GitBranch::new(
                repo_url.to_string(),
                branch.clone(),
                default_workdir(repo_url, &branch),
                ssh_env,
                tuning.min_push_interval,
                tuning.max_blob_bytes,
                tuning.trace_frames,
                tuning.defer_cleanup,
                Some((*cipher).clone()),
            ),
            session_id: session_id.to_string(),
            tx_seq: AtomicU64::new(1),
        })
    }

    pub fn publish(&self, payload: ControlPayload) -> Result<()> {
        let seq = self.tx_seq.fetch_add(1, Ordering::SeqCst);
        self.relay
            .write_frames(vec![Frame::new(
                self.session_id.clone(),
                0,
                Direction::ClientToExit,
                seq,
                0,
                FramePayload::Control(payload),
            )])
            .map(|_| ())
    }

    pub fn ensure_ready(&self) -> Result<()> {
        self.relay.ensure_ready()
    }

    pub fn poll(&self) -> Result<Vec<ControlPayload>> {
        let mut frames = self
            .relay
            .read_frames()
            .context("failed to read control branch")?;
        frames.sort_by_key(|stored| stored.frame.header.seq);
        Ok(frames
            .into_iter()
            .filter(|stored| stored.frame.header.session_id == self.session_id)
            .filter_map(|stored| match stored.frame.payload {
                FramePayload::Control(payload) => Some(payload),
                _ => None,
            })
            .collect())
    }
}

pub fn control_branch_name(session_id: &str) -> String {
    format!("gt/{}/ctl", safe_component(session_id))
}

fn default_workdir(repo_url: &str, branch_name: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(repo_url.as_bytes());
    hasher.update(b"\0");
    hasher.update(branch_name.as_bytes());
    let hash = hex::encode(hasher.finalize());
    std::env::temp_dir()
        .join("gittunnel")
        .join("control")
        .join(&hash[..16])
}

pub(crate) fn default_control_tuning() -> PushTuning {
    PushTuning::new(
        std::time::Duration::from_millis(0),
        std::time::Duration::from_millis(400),
        false,
        true,
        DEFAULT_MAX_BLOB_BYTES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_branch_uses_session_namespace() {
        assert_eq!(control_branch_name("session"), "gt/session/ctl");
    }
}
