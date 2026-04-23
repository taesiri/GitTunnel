use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::control::{default_control_tuning, ControlChannel};
use crate::crypto::TunnelCipher;
use crate::frame::{safe_component, ControlPayload, FramePayload};
use crate::git_relay::DEFAULT_MAX_BLOB_BYTES;
use crate::socks::{self, ReplyCode};
use crate::stream::{StreamChannel, INITIAL_POLL_INTERVAL, MAX_POLL_INTERVAL};

const DEFAULT_CHUNK_SIZE: usize = 32 * 1024;
const DISCOVERY_POLL_INTERVAL: Duration = Duration::from_millis(400);

pub struct Session {
    session_id: String,
    repo_url: String,
    ssh_env: Option<String>,
    cipher: Arc<TunnelCipher>,
    streams: Mutex<HashMap<StreamKey, Arc<StreamChannel>>>,
    next_sid: AtomicU64,
    next_lease_id: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StreamKey {
    sid: u64,
    lease_id: u64,
}

#[derive(Clone)]
struct StreamLease {
    sid: u64,
    lease_id: u64,
    stream: Arc<StreamChannel>,
}

struct WarmPool {
    target_size: usize,
    idle: Mutex<VecDeque<StreamLease>>,
}

#[derive(Default)]
struct ExitControlState {
    open_requests: HashMap<StreamKey, (String, u16)>,
    seen_control: HashSet<StreamKey>,
    closed_control: HashSet<StreamKey>,
    idle_discovery_sids: HashSet<u64>,
}

impl WarmPool {
    fn new(target_size: usize) -> Self {
        Self {
            target_size,
            idle: Mutex::new(VecDeque::new()),
        }
    }

    fn take(&self) -> Option<StreamLease> {
        self.idle
            .lock()
            .expect("warm pool mutex poisoned")
            .pop_front()
    }

    fn put(&self, lease: StreamLease) -> bool {
        let mut idle = self.idle.lock().expect("warm pool mutex poisoned");
        if idle.len() >= self.target_size
            || idle
                .iter()
                .any(|existing| existing.sid == lease.sid && existing.lease_id == lease.lease_id)
        {
            return false;
        }
        idle.push_back(lease);
        true
    }

    fn len(&self) -> usize {
        self.idle.lock().expect("warm pool mutex poisoned").len()
    }
}

impl Session {
    pub fn new(
        repo_url: &str,
        session_id: &str,
        cipher: Arc<TunnelCipher>,
        ssh_env: Option<String>,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            repo_url: repo_url.to_string(),
            ssh_env,
            cipher,
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU64::new(1),
            next_lease_id: AtomicU64::new(1),
        }
    }

    pub async fn run_client(
        self: Arc<Self>,
        listen: SocketAddr,
        allow_byte_cap: u64,
        max_runtime: Duration,
        warm_pool_size: usize,
    ) -> Result<()> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("failed to bind {listen}"))?;
        let local_addr = listener.local_addr()?;
        let budget = ByteBudget::new(allow_byte_cap);
        let control = self.control_channel()?;
        ensure_control_channel(control.clone()).await?;
        let warm_pool = if warm_pool_size > 0 {
            let pool = Arc::new(WarmPool::new(warm_pool_size));
            self.prewarm_pool(pool.clone()).await?;
            Some(pool)
        } else {
            None
        };
        let deadline = sleep(max_runtime);
        tokio::pin!(deadline);

        info!(listen = %local_addr, session = %self.session_id, "v2 SOCKS5 client listening");

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (socket, peer) = accepted.context("failed to accept SOCKS5 connection")?;
                    let session = self.clone();
                    let control = control.clone();
                    let budget = budget.clone();
                    let warm_pool = warm_pool.clone();
                    tokio::spawn(async move {
                        if let Err(error) = session.handle_client_socket(socket, peer, control, budget, warm_pool).await {
                            warn!(%peer, %error, "v2 client stream ended with error");
                        }
                    });
                }
                _ = &mut deadline => {
                    info!("v2 client max runtime reached");
                    return Ok(());
                }
            }
        }
    }

    pub async fn run_exit(
        self: Arc<Self>,
        allow_hosts: Vec<String>,
        byte_cap: u64,
        max_runtime: Duration,
    ) -> Result<()> {
        let allowlist = AllowList::new(allow_hosts);
        let budget = ByteBudget::new(byte_cap);
        let control = self.control_channel()?;
        ensure_control_channel(control.clone()).await?;
        let mut control_state = ExitControlState::default();
        let deadline = sleep(max_runtime);
        tokio::pin!(deadline);

        info!(session = %self.session_id, "v2 exit side polling stream refs");

        loop {
            tokio::select! {
                _ = sleep(DISCOVERY_POLL_INTERVAL) => {
                    if let Err(error) = self.process_exit_tick(
                        control.clone(),
                        &allowlist,
                        &budget,
                        &mut control_state,
                    ).await {
                        warn!(%error, "v2 exit poll failed");
                    }
                }
                _ = &mut deadline => {
                    info!("v2 exit max runtime reached");
                    return Ok(());
                }
            }
        }
    }

    fn control_channel(&self) -> Result<Arc<ControlChannel>> {
        Ok(Arc::new(ControlChannel::new(
            &self.repo_url,
            &self.session_id,
            self.ssh_env.clone(),
            self.cipher.clone(),
            default_control_tuning(),
        )?))
    }

    async fn prewarm_pool(self: &Arc<Self>, pool: Arc<WarmPool>) -> Result<()> {
        let mut tasks = Vec::with_capacity(pool.target_size);
        for _ in 0..pool.target_size {
            let session = self.clone();
            tasks.push(tokio::spawn(
                async move { session.create_stream_lease().await },
            ));
        }

        for task in tasks {
            let lease = task.await.context("warm pool setup task failed")??;
            let sid = lease.sid;
            let lease_id = lease.lease_id;
            if pool.put(lease.clone()) {
                info!(
                    sid,
                    lease_id,
                    idle = pool.len(),
                    target = pool.target_size,
                    "warm_pool_ready"
                );
            }
        }
        Ok(())
    }

    async fn acquire_stream_lease(
        self: &Arc<Self>,
        warm_pool: Option<Arc<WarmPool>>,
    ) -> Result<StreamLease> {
        if let Some(pool) = warm_pool {
            if let Some(lease) = pool.take() {
                info!(
                    sid = lease.sid,
                    lease_id = lease.lease_id,
                    idle = pool.len(),
                    "warm_pool_hit"
                );
                return Ok(lease);
            }
            info!(target = pool.target_size, "warm_pool_miss");
        }
        self.create_stream_lease().await
    }

    async fn create_stream_lease(self: &Arc<Self>) -> Result<StreamLease> {
        let started = Instant::now();
        let sid = self.next_sid.fetch_add(1, Ordering::SeqCst);
        let lease_id = self.next_lease_id.fetch_add(1, Ordering::SeqCst);
        let stream = Arc::new(StreamChannel::new(
            sid,
            &self.repo_url,
            &self.session_id,
            "c2e",
            "e2c",
            self.ssh_env.clone(),
            self.cipher.clone(),
            DEFAULT_MAX_BLOB_BYTES,
        )?);
        stream.ensure_ready().await?;
        info!(
            sid,
            lease_id,
            setup_ms = started.elapsed().as_millis(),
            c2e = %crate::stream::stream_branch_name(&self.session_id, sid, "c2e"),
            e2c = %crate::stream::stream_branch_name(&self.session_id, sid, "e2c"),
            "stream_lease_ready"
        );
        Ok(StreamLease {
            sid,
            lease_id,
            stream,
        })
    }

    async fn recycle_stream_lease(self: &Arc<Self>, mut lease: StreamLease, pool: Arc<WarmPool>) {
        let started = Instant::now();
        info!(
            sid = lease.sid,
            lease_id = lease.lease_id,
            "warm_pool_recycle_start"
        );
        match lease.stream.reset_for_reuse().await {
            Ok(()) => {
                lease.lease_id = self.next_lease_id.fetch_add(1, Ordering::SeqCst);
                let sid = lease.sid;
                let lease_id = lease.lease_id;
                if pool.put(lease.clone()) {
                    info!(
                        sid,
                        lease_id,
                        reset_ms = started.elapsed().as_millis(),
                        idle = pool.len(),
                        "warm_pool_recycle_done"
                    );
                } else {
                    warn!(
                        sid,
                        lease_id, "warm pool full; deleting recycled stream branches"
                    );
                    if let Err(error) = lease.stream.delete_branches().await {
                        warn!(sid, lease_id, %error, "failed to delete extra warm pool branches");
                    }
                }
            }
            Err(error) => {
                warn!(
                    sid = lease.sid,
                    lease_id = lease.lease_id,
                    %error,
                    "warm_pool_recycle_failed"
                );
                if let Err(delete_error) = lease.stream.delete_branches().await {
                    warn!(
                        sid = lease.sid,
                        lease_id = lease.lease_id,
                        %delete_error,
                        "failed to delete failed warm pool branches"
                    );
                }
                match self.create_stream_lease().await {
                    Ok(replacement) => {
                        let _ = pool.put(replacement);
                    }
                    Err(replacement_error) => {
                        warn!(%replacement_error, "failed to replenish warm pool");
                    }
                }
            }
        }
    }

    async fn handle_client_socket(
        self: Arc<Self>,
        mut socket: TcpStream,
        peer: SocketAddr,
        control: Arc<ControlChannel>,
        budget: ByteBudget,
        warm_pool: Option<Arc<WarmPool>>,
    ) -> Result<()> {
        let accepted_at = Instant::now();
        let target = match socks::accept_connect(&mut socket).await {
            Ok(target) => target,
            Err(error) => {
                let _ = socks::send_reply(&mut socket, ReplyCode::GeneralFailure).await;
                return Err(error);
            }
        };

        let lease_acquire_started = Instant::now();
        let lease = self.acquire_stream_lease(warm_pool.clone()).await?;
        let key = StreamKey {
            sid: lease.sid,
            lease_id: lease.lease_id,
        };
        info!(
            sid = key.sid,
            lease_id = key.lease_id,
            accept_to_lease_ms = accepted_at.elapsed().as_millis(),
            lease_acquire_ms = lease_acquire_started.elapsed().as_millis(),
            "v2 stream lease acquired"
        );
        publish_control(
            control.clone(),
            ControlPayload::StreamOpen {
                sid: lease.sid,
                lease_id: lease.lease_id,
                host: target.host.clone(),
                port: target.port,
            },
        )
        .await?;

        socks::send_reply(&mut socket, ReplyCode::Succeeded).await?;
        self.streams
            .lock()
            .expect("session stream mutex poisoned")
            .insert(key, lease.stream.clone());

        info!(%peer, sid = key.sid, lease_id = key.lease_id, target = %target, "accepted v2 SOCKS5 CONNECT");

        let (reader, writer) = socket.into_split();
        let run_result =
            run_stream_pair(reader, writer, lease.stream.clone(), budget, accepted_at).await;
        let control_result = if let Err(error) = &run_result {
            publish_control(
                control,
                ControlPayload::StreamReset {
                    sid: lease.sid,
                    lease_id: lease.lease_id,
                    reason: error.to_string(),
                },
            )
            .await
        } else {
            publish_control(
                control,
                ControlPayload::StreamClose {
                    sid: lease.sid,
                    lease_id: lease.lease_id,
                    final_seq_c2e: lease.stream.last_sent_seq(),
                    final_seq_e2c: 0,
                },
            )
            .await
        };
        self.streams
            .lock()
            .expect("session stream mutex poisoned")
            .remove(&key);
        let can_recycle = run_result.is_ok() && control_result.is_ok();
        match (can_recycle, warm_pool) {
            (true, Some(pool)) => self.recycle_stream_lease(lease, pool).await,
            (false, Some(_)) => {
                let close_result = lease.stream.delete_branches().await;
                if let Err(error) = close_result {
                    warn!(sid = key.sid, lease_id = key.lease_id, %error, "v2 stream branch delete failed");
                }
            }
            (_, None) => {
                let close_result = lease.stream.close().await;
                if let Err(error) = close_result {
                    warn!(sid = key.sid, lease_id = key.lease_id, %error, "v2 stream close failed");
                }
            }
        }
        run_result?;
        control_result
    }

    async fn process_exit_tick(
        self: &Arc<Self>,
        control: Arc<ControlChannel>,
        allowlist: &AllowList,
        budget: &ByteBudget,
        control_state: &mut ExitControlState,
    ) -> Result<()> {
        for payload in poll_control(control.clone()).await? {
            match payload {
                ControlPayload::StreamOpen {
                    sid,
                    lease_id,
                    host,
                    port,
                } => {
                    let key = StreamKey { sid, lease_id };
                    control_state.idle_discovery_sids.remove(&sid);
                    if !control_state.closed_control.contains(&key)
                        && control_state.seen_control.insert(key)
                    {
                        control_state.open_requests.insert(key, (host, port));
                    }
                }
                ControlPayload::SessionBye { reason } => {
                    info!(%reason, "v2 peer ended session");
                }
                ControlPayload::StreamReset {
                    sid,
                    lease_id,
                    reason,
                } => {
                    let key = StreamKey { sid, lease_id };
                    control_state.open_requests.remove(&key);
                    control_state.closed_control.insert(key);
                    warn!(sid, lease_id, %reason, "v2 peer reset stream");
                }
                ControlPayload::StreamClose { sid, lease_id, .. } => {
                    let key = StreamKey { sid, lease_id };
                    control_state.open_requests.remove(&key);
                    control_state.closed_control.insert(key);
                    debug!(sid, lease_id, "v2 peer closed stream");
                }
                ControlPayload::SessionHello { .. } => {}
            }
        }

        let ready_keys = control_state
            .open_requests
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for key in ready_keys {
            if self
                .streams
                .lock()
                .expect("session stream mutex poisoned")
                .contains_key(&key)
            {
                continue;
            }
            let Some(target) = control_state.open_requests.remove(&key) else {
                continue;
            };
            self.open_exit_stream(control.clone(), allowlist, budget, key, target)
                .await?;
        }

        let refs = self.list_c2e_stream_refs().await?;
        for sid in refs {
            if control_state.idle_discovery_sids.contains(&sid)
                || control_state.open_requests.keys().any(|key| key.sid == sid)
                || self
                    .streams
                    .lock()
                    .expect("session stream mutex poisoned")
                    .keys()
                    .any(|key| key.sid == sid)
            {
                continue;
            }

            let key = StreamKey { sid, lease_id: 0 };
            if self
                .streams
                .lock()
                .expect("session stream mutex poisoned")
                .contains_key(&key)
            {
                continue;
            }

            let stream = Arc::new(StreamChannel::new(
                sid,
                &self.repo_url,
                &self.session_id,
                "e2c",
                "c2e",
                self.ssh_env.clone(),
                self.cipher.clone(),
                DEFAULT_MAX_BLOB_BYTES,
            )?);
            match parse_open_from_stream(stream.clone()).await? {
                Some(target) => {
                    self.open_exit_stream(control.clone(), allowlist, budget, key, target)
                        .await?;
                }
                None => {
                    control_state.idle_discovery_sids.insert(sid);
                }
            }
        }
        Ok(())
    }

    async fn open_exit_stream(
        self: &Arc<Self>,
        control: Arc<ControlChannel>,
        allowlist: &AllowList,
        budget: &ByteBudget,
        key: StreamKey,
        target: (String, u16),
    ) -> Result<()> {
        let (host, port) = target;
        if !allowlist.allows(&host, port) {
            warn!(sid = key.sid, lease_id = key.lease_id, target = %format!("{host}:{port}"), "v2 target denied by allowlist");
            publish_control(
                control,
                ControlPayload::StreamReset {
                    sid: key.sid,
                    lease_id: key.lease_id,
                    reason: "target denied".to_string(),
                },
            )
            .await?;
            return Ok(());
        }

        let stream = Arc::new(StreamChannel::new(
            key.sid,
            &self.repo_url,
            &self.session_id,
            "e2c",
            "c2e",
            self.ssh_env.clone(),
            self.cipher.clone(),
            DEFAULT_MAX_BLOB_BYTES,
        )?);
        stream.ensure_ready().await?;
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(remote) => {
                self.streams
                    .lock()
                    .expect("session stream mutex poisoned")
                    .insert(key, stream.clone());
                let session = self.clone();
                let budget = budget.clone();
                tokio::spawn(async move {
                    let (reader, writer) = remote.into_split();
                    let run_result =
                        run_stream_pair(reader, writer, stream.clone(), budget, Instant::now())
                            .await;
                    session
                        .streams
                        .lock()
                        .expect("session stream mutex poisoned")
                        .remove(&key);
                    if let Err(error) = run_result {
                        warn!(sid = key.sid, lease_id = key.lease_id, %error, "v2 exit stream ended with error");
                    }
                });
                info!(sid = key.sid, lease_id = key.lease_id, target = %format!("{host}:{port}"), "opened v2 exit TCP connection");
            }
            Err(error) => {
                warn!(sid = key.sid, lease_id = key.lease_id, target = %format!("{host}:{port}"), %error, "failed to connect v2 exit target");
                publish_control(
                    control,
                    ControlPayload::StreamReset {
                        sid: key.sid,
                        lease_id: key.lease_id,
                        reason: "connect failed".to_string(),
                    },
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn list_c2e_stream_refs(&self) -> Result<Vec<u64>> {
        let repo_url = self.repo_url.clone();
        let session_id = self.session_id.clone();
        let ssh_env = self.ssh_env.clone();
        tokio::task::spawn_blocking(move || {
            list_c2e_stream_refs_blocking(&repo_url, &session_id, ssh_env)
        })
        .await
        .context("stream ref discovery task failed")?
    }
}

async fn run_stream_pair(
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    stream: Arc<StreamChannel>,
    budget: ByteBudget,
    started_at: Instant,
) -> Result<()> {
    let mut upload = tokio::spawn(write_loop(reader, stream.clone(), budget.clone()));
    let mut download = tokio::spawn(read_loop(writer, stream, budget, started_at));
    let mut upload_done = false;
    let mut download_done = false;

    loop {
        tokio::select! {
            result = &mut upload, if !upload_done => {
                if let Err(error) = flatten_join(result, "stream upload task") {
                    download.abort();
                    return Err(error);
                }
                upload_done = true;
            }
            result = &mut download, if !download_done => {
                if let Err(error) = flatten_join(result, "stream download task") {
                    upload.abort();
                    return Err(error);
                }
                download_done = true;
            }
        }

        if upload_done && download_done {
            return Ok(());
        }
    }
}

fn flatten_join(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    task_name: &str,
) -> Result<()> {
    result.with_context(|| format!("{task_name} failed"))?
}

async fn write_loop(
    mut reader: OwnedReadHalf,
    stream: Arc<StreamChannel>,
    budget: ByteBudget,
) -> Result<()> {
    let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .context("failed to read local TCP socket")?;
        if n == 0 {
            stream
                .write_frames(vec![stream.next_frame(FramePayload::HalfClose)])
                .await?;
            return Ok(());
        }

        budget.add(n)?;
        stream
            .write_frames(vec![stream.next_frame(FramePayload::data(&buf[..n]))])
            .await?;
        info!(sid = stream.sid, bytes = n, "sent v2 data frame");
    }
}

async fn read_loop(
    mut writer: OwnedWriteHalf,
    stream: Arc<StreamChannel>,
    budget: ByteBudget,
    started_at: Instant,
) -> Result<()> {
    let mut seen = HashSet::<u64>::new();
    let mut poll_interval = INITIAL_POLL_INTERVAL;
    let mut first_response_logged = false;

    loop {
        sleep(poll_interval).await;
        let frames = stream.read_frames().await?;
        if frames.is_empty() {
            poll_interval = (poll_interval * 2).min(MAX_POLL_INTERVAL);
            continue;
        }
        poll_interval = INITIAL_POLL_INTERVAL;

        for stored in frames {
            let seq = stored.frame.header.seq;
            if !seen.insert(seq) {
                continue;
            }

            match stored.frame.payload {
                FramePayload::Data { .. } => {
                    if !first_response_logged {
                        first_response_logged = true;
                        info!(
                            sid = stream.sid,
                            first_response_ms = started_at.elapsed().as_millis(),
                            "first_response_frame_observed"
                        );
                    }
                    let data = stored.frame.payload.data_bytes()?;
                    budget.add(data.len())?;
                    writer
                        .write_all(&data)
                        .await
                        .context("failed to write local TCP socket")?;
                    info!(
                        sid = stream.sid,
                        bytes = data.len(),
                        "received v2 data frame"
                    );
                }
                FramePayload::HalfClose => {
                    stream.mark_remote_half_closed();
                    writer.shutdown().await.ok();
                    return Ok(());
                }
                FramePayload::Close => {
                    writer.shutdown().await.ok();
                    return Ok(());
                }
                FramePayload::Reset { reason } => bail!("stream reset: {reason}"),
                FramePayload::Open { .. } | FramePayload::Ack { .. } | FramePayload::Control(_) => {
                }
            }
        }
    }
}

async fn publish_control(control: Arc<ControlChannel>, payload: ControlPayload) -> Result<()> {
    tokio::task::spawn_blocking(move || control.publish(payload))
        .await
        .context("control publish task failed")?
}

async fn ensure_control_channel(control: Arc<ControlChannel>) -> Result<()> {
    tokio::task::spawn_blocking(move || control.ensure_ready())
        .await
        .context("control setup task failed")?
}

async fn poll_control(control: Arc<ControlChannel>) -> Result<Vec<ControlPayload>> {
    tokio::task::spawn_blocking(move || control.poll())
        .await
        .context("control poll task failed")?
}

async fn parse_open_from_stream(stream: Arc<StreamChannel>) -> Result<Option<(String, u16)>> {
    let frames = stream.read_frames().await?;
    Ok(frames
        .into_iter()
        .find_map(|stored| match stored.frame.payload {
            FramePayload::Open { host, port } => Some((host, port)),
            _ => None,
        }))
}

fn list_c2e_stream_refs_blocking(
    repo_url: &str,
    session_id: &str,
    ssh_env: Option<String>,
) -> Result<Vec<u64>> {
    let session = safe_component(session_id);
    let pattern = format!("refs/heads/gt/{session}/s/*/c2e");
    let mut command = Command::new("git");
    if let Some(ssh_env) = ssh_env {
        command.env("GIT_SSH_COMMAND", ssh_env);
    }
    let output = command
        .args(["ls-remote", "--heads", repo_url, &pattern])
        .output()
        .context("failed to run git ls-remote")?;
    if !output.status.success() {
        bail!(
            "git ls-remote failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let prefix = format!("refs/heads/gt/{session}/s/");
    let mut sids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|reference| {
            reference
                .strip_prefix(&prefix)
                .and_then(|tail| tail.strip_suffix("/c2e"))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        })
        .collect::<Vec<_>>();
    sids.sort_unstable();
    sids.dedup();
    Ok(sids)
}

#[derive(Clone)]
struct ByteBudget {
    cap: u64,
    used: Arc<AtomicU64>,
}

impl ByteBudget {
    fn new(cap: u64) -> Self {
        Self {
            cap,
            used: Arc::new(AtomicU64::new(0)),
        }
    }

    fn add(&self, bytes: usize) -> Result<()> {
        let bytes = bytes as u64;
        let previous = self.used.fetch_add(bytes, Ordering::SeqCst);
        let current = previous.saturating_add(bytes);
        if current > self.cap {
            bail!("demo byte cap exceeded: {} > {}", current, self.cap);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AllowList {
    patterns: Vec<HostPattern>,
}

impl AllowList {
    fn new(mut raw_patterns: Vec<String>) -> Self {
        if raw_patterns.is_empty() {
            raw_patterns = vec!["example.com:80".to_string(), "example.com:443".to_string()];
        }
        let patterns = raw_patterns
            .into_iter()
            .filter_map(|raw| match HostPattern::parse(&raw) {
                Ok(pattern) => Some(pattern),
                Err(error) => {
                    warn!(pattern = %raw, %error, "ignoring invalid allow-host pattern");
                    None
                }
            })
            .collect();
        Self { patterns }
    }

    fn allows(&self, host: &str, port: u16) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches(host, port))
    }
}

#[derive(Debug, Clone)]
struct HostPattern {
    host: String,
    port: Option<u16>,
}

impl HostPattern {
    fn parse(raw: &str) -> Result<Self> {
        let (host, port) = raw
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("pattern must be host:port"))?;
        let host = host.trim().trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            bail!("host must not be empty");
        }
        let port = if port == "*" {
            None
        } else {
            Some(port.parse::<u16>().context("invalid port")?)
        };
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|allowed| allowed != port) {
            return false;
        }
        let host = host.to_ascii_lowercase();
        self.host == "*"
            || self.host == host
            || self
                .host
                .strip_prefix("*.")
                .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;
    use crate::crypto::TunnelCipher;

    #[test]
    fn stream_keys_allow_reused_sid_with_new_lease() {
        let mut seen = HashSet::new();
        assert!(seen.insert(StreamKey {
            sid: 1,
            lease_id: 10,
        }));
        assert!(seen.insert(StreamKey {
            sid: 1,
            lease_id: 11,
        }));
        assert!(!seen.insert(StreamKey {
            sid: 1,
            lease_id: 10,
        }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warm_pool_startup_creates_unique_branch_pairs() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let session = Arc::new(Session::new(
            bare.to_string_lossy().as_ref(),
            "session",
            Arc::new(TunnelCipher::from_key_bytes([12; 32])),
            None,
        ));
        let pool = Arc::new(WarmPool::new(2));
        session.prewarm_pool(pool.clone()).await.unwrap();

        assert_eq!(pool.len(), 2);
        let first = pool.take().unwrap();
        let second = pool.take().unwrap();
        assert_ne!(first.sid, second.sid);
        assert_ne!(first.lease_id, second.lease_id);
        assert!(pool.take().is_none());

        let refs = Command::new("git")
            .args(["show-ref"])
            .current_dir(&bare)
            .output()
            .unwrap();
        assert!(refs.status.success());
        let refs = String::from_utf8_lossy(&refs.stdout);
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000001/c2e"));
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000001/e2c"));
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000002/c2e"));
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000002/e2c"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warm_pool_recycle_reuses_sid_with_new_lease_id() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let session = Arc::new(Session::new(
            bare.to_string_lossy().as_ref(),
            "session",
            Arc::new(TunnelCipher::from_key_bytes([13; 32])),
            None,
        ));
        let pool = Arc::new(WarmPool::new(1));
        session.prewarm_pool(pool.clone()).await.unwrap();

        let lease = pool.take().unwrap();
        let sid = lease.sid;
        let old_lease_id = lease.lease_id;
        lease
            .stream
            .write_frames(vec![lease.stream.next_frame(FramePayload::data(b"before"))])
            .await
            .unwrap();

        session.recycle_stream_lease(lease, pool.clone()).await;

        let recycled = pool.take().unwrap();
        assert_eq!(recycled.sid, sid);
        assert_ne!(recycled.lease_id, old_lease_id);
        assert_eq!(recycled.stream.last_sent_seq(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warm_pool_allocation_never_returns_same_idle_lease_twice() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let session = Arc::new(Session::new(
            bare.to_string_lossy().as_ref(),
            "session",
            Arc::new(TunnelCipher::from_key_bytes([14; 32])),
            None,
        ));
        let pool = Arc::new(WarmPool::new(1));
        session.prewarm_pool(pool.clone()).await.unwrap();

        let first = pool.take();
        let second = pool.take();
        assert!(first.is_some());
        assert!(second.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warm_pool_miss_creates_cold_branch_pair() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let session = Arc::new(Session::new(
            bare.to_string_lossy().as_ref(),
            "session",
            Arc::new(TunnelCipher::from_key_bytes([15; 32])),
            None,
        ));
        let pool = Arc::new(WarmPool::new(1));
        let lease = session
            .acquire_stream_lease(Some(pool.clone()))
            .await
            .unwrap();

        assert_eq!(lease.sid, 1);
        assert_eq!(lease.lease_id, 1);
        assert_eq!(pool.len(), 0);

        let refs = Command::new("git")
            .args(["show-ref"])
            .current_dir(&bare)
            .output()
            .unwrap();
        assert!(refs.status.success());
        let refs = String::from_utf8_lossy(&refs.stdout);
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000001/c2e"));
        assert!(refs.contains("refs/heads/gt/session/s/0000000000000001/e2c"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exit_control_replay_does_not_reopen_closed_lease() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let session = Arc::new(Session::new(
            bare.to_string_lossy().as_ref(),
            "session",
            Arc::new(TunnelCipher::from_key_bytes([16; 32])),
            None,
        ));
        let control = session.control_channel().unwrap();
        ensure_control_channel(control.clone()).await.unwrap();
        let key = StreamKey {
            sid: 1,
            lease_id: 22,
        };
        publish_control(
            control.clone(),
            ControlPayload::StreamOpen {
                sid: key.sid,
                lease_id: key.lease_id,
                host: "127.0.0.1".to_string(),
                port: 9,
            },
        )
        .await
        .unwrap();
        publish_control(
            control.clone(),
            ControlPayload::StreamClose {
                sid: key.sid,
                lease_id: key.lease_id,
                final_seq_c2e: 0,
                final_seq_e2c: 0,
            },
        )
        .await
        .unwrap();

        let mut control_state = ExitControlState::default();
        session
            .process_exit_tick(
                control,
                &AllowList::new(vec!["127.0.0.1:9".to_string()]),
                &ByteBudget::new(1024),
                &mut control_state,
            )
            .await
            .unwrap();

        assert!(control_state.open_requests.is_empty());
        assert!(control_state.seen_control.contains(&key));
        assert!(control_state.closed_control.contains(&key));
        assert!(session
            .streams
            .lock()
            .expect("session stream mutex poisoned")
            .is_empty());
    }
}
