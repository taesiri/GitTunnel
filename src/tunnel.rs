use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use crate::frame::{Direction, Frame, FramePayload, StoredFrame};
use crate::git_relay::GitRelay;
use crate::socks::{self, ReplyCode};

#[derive(Clone)]
pub struct ClientOptions {
    pub relay: GitRelay,
    pub listen: SocketAddr,
    pub chunk_size: usize,
    pub data_batch_size: Option<usize>,
    pub batch_flush_interval: Duration,
    pub ack_data_frames: bool,
    pub byte_cap: u64,
    pub max_runtime: Duration,
}

#[derive(Clone)]
pub struct ExitOptions {
    pub relay: GitRelay,
    pub allow_hosts: Vec<String>,
    pub chunk_size: usize,
    pub data_batch_size: Option<usize>,
    pub batch_flush_interval: Duration,
    pub ack_data_frames: bool,
    pub byte_cap: u64,
    pub max_runtime: Duration,
}

#[derive(Clone)]
struct ByteBudget {
    cap: u64,
    used: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy)]
struct TransferSettings {
    chunk_size: usize,
    data_batch_size: Option<usize>,
    batch_flush_interval: Duration,
    ack_data_frames: bool,
}

struct UploadOptions {
    session_id: String,
    stream_id: u64,
    tx_seq: Arc<AtomicU64>,
    budget: ByteBudget,
    settings: TransferSettings,
    initial_frame: Option<Frame>,
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

pub async fn run_client(options: ClientOptions) -> Result<()> {
    let listener = TcpListener::bind(options.listen)
        .await
        .with_context(|| format!("failed to bind {}", options.listen))?;
    run_client_with_listener(listener, options).await
}

async fn run_client_with_listener(listener: TcpListener, options: ClientOptions) -> Result<()> {
    let local_addr = listener.local_addr()?;
    let budget = ByteBudget::new(options.byte_cap);
    let next_stream_id = Arc::new(AtomicU64::new(1));
    info!(
        listen = %local_addr,
        session = %options.relay.session_id(),
        "SOCKS5 client listening"
    );

    let deadline = sleep(options.max_runtime);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (socket, peer) = accept.context("failed to accept SOCKS5 connection")?;
                let stream_id = next_stream_id.fetch_add(1, Ordering::SeqCst);
                let relay = options.relay.clone();
                let budget = budget.clone();
                let settings = TransferSettings {
                    chunk_size: options.chunk_size,
                    data_batch_size: options.data_batch_size,
                    batch_flush_interval: options.batch_flush_interval,
                    ack_data_frames: options.ack_data_frames,
                };
                tokio::spawn(async move {
                    if let Err(error) = handle_client_socket(
                        socket,
                        peer,
                        relay,
                        stream_id,
                        budget,
                        settings,
                    ).await {
                        warn!(%peer, stream_id, %error, "client stream ended with error");
                    }
                });
            }
            _ = &mut deadline => {
                info!("client max runtime reached");
                return Ok(());
            }
        }
    }
}

async fn handle_client_socket(
    mut socket: TcpStream,
    peer: SocketAddr,
    relay: GitRelay,
    stream_id: u64,
    budget: ByteBudget,
    settings: TransferSettings,
) -> Result<()> {
    let target = match socks::accept_connect(&mut socket).await {
        Ok(target) => target,
        Err(error) => {
            let _ = socks::send_reply(&mut socket, ReplyCode::GeneralFailure).await;
            return Err(error);
        }
    };
    info!(%peer, stream_id, target = %target, "accepted SOCKS5 CONNECT");

    let session_id = relay.session_id().to_string();
    let tx_seq = Arc::new(AtomicU64::new(1));
    let open_frame = next_frame(
        &session_id,
        stream_id,
        Direction::ClientToExit,
        &tx_seq,
        0,
        FramePayload::Open {
            host: target.host.clone(),
            port: target.port,
        },
    );
    let initial_upload_frame = if settings.data_batch_size.is_some() {
        Some(open_frame)
    } else {
        relay
            .write_frame(open_frame)
            .await
            .context("failed to send open frame")?;
        None
    };

    socks::send_reply(&mut socket, ReplyCode::Succeeded).await?;
    let (reader, writer) = socket.into_split();

    let upload = tokio::spawn(upload_local_to_relay(
        reader,
        relay.clone(),
        UploadOptions {
            session_id: session_id.clone(),
            stream_id,
            tx_seq: tx_seq.clone(),
            budget: budget.clone(),
            settings,
            initial_frame: initial_upload_frame,
        },
    ));
    let download = download_relay_to_local(
        writer,
        relay.clone(),
        session_id,
        stream_id,
        tx_seq,
        budget,
        settings,
    )
    .await;
    upload.abort();
    download
}

async fn upload_local_to_relay(
    mut reader: OwnedReadHalf,
    relay: GitRelay,
    options: UploadOptions,
) -> Result<()> {
    let mut buf = vec![0u8; options.settings.chunk_size];
    let mut pending = options.initial_frame.into_iter().collect::<Vec<_>>();
    let mut pending_bytes = 0usize;
    loop {
        let read_result = if options.settings.data_batch_size.is_some() {
            match timeout(options.settings.batch_flush_interval, reader.read(&mut buf)).await {
                Ok(result) => Some(result),
                Err(_) => {
                    if !pending.is_empty() {
                        flush_frame_batch(&relay, &mut pending, &mut pending_bytes).await?;
                    }
                    None
                }
            }
        } else {
            Some(reader.read(&mut buf).await)
        };

        let Some(read_result) = read_result else {
            continue;
        };
        let n = read_result.context("failed to read local socket")?;
        if n == 0 {
            flush_frame_batch(&relay, &mut pending, &mut pending_bytes).await?;
            send_with_next_seq(
                &relay,
                &options.session_id,
                options.stream_id,
                Direction::ClientToExit,
                &options.tx_seq,
                0,
                FramePayload::HalfClose,
            )
            .await?;
            debug!(stream_id = options.stream_id, "local socket half-closed");
            return Ok(());
        }
        options.budget.add(n)?;
        let frame = next_frame(
            &options.session_id,
            options.stream_id,
            Direction::ClientToExit,
            &options.tx_seq,
            0,
            FramePayload::data(&buf[..n]),
        );
        if let Some(batch_size) = options.settings.data_batch_size {
            pending_bytes += n;
            pending.push(frame);
            if pending_bytes >= batch_size {
                flush_frame_batch(&relay, &mut pending, &mut pending_bytes).await?;
            }
        } else {
            relay.write_frame(frame).await?;
        }
        info!(
            stream_id = options.stream_id,
            bytes = n,
            "sent client data frame"
        );
    }
}

async fn download_relay_to_local(
    mut writer: OwnedWriteHalf,
    relay: GitRelay,
    session_id: String,
    stream_id: u64,
    tx_seq: Arc<AtomicU64>,
    budget: ByteBudget,
    settings: TransferSettings,
) -> Result<()> {
    let mut seen = HashSet::<u64>::new();
    let mut last_ack = 0;
    let mut ticks = interval(relay.poll_interval());
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        ticks.tick().await;
        let frames = relay.read_frames(Some(Direction::ExitToClient)).await?;
        for stored in frames_for_stream(frames, &session_id, stream_id) {
            let seq = stored.frame.header.seq;
            if !seen.insert(seq) {
                continue;
            }
            let payload = stored.frame.payload;
            match payload {
                FramePayload::Data { .. } => {
                    let data = payload.data_bytes()?;
                    budget.add(data.len())?;
                    writer
                        .write_all(&data)
                        .await
                        .context("failed to write local socket")?;
                    last_ack = last_ack.max(seq);
                    if settings.ack_data_frames {
                        send_ack(
                            &relay,
                            &session_id,
                            stream_id,
                            Direction::ClientToExit,
                            Direction::ExitToClient,
                            &tx_seq,
                            last_ack,
                        )
                        .await?;
                    }
                    info!(stream_id, bytes = data.len(), "received exit data frame");
                }
                FramePayload::HalfClose => {
                    writer.shutdown().await.ok();
                    last_ack = last_ack.max(seq);
                    send_ack(
                        &relay,
                        &session_id,
                        stream_id,
                        Direction::ClientToExit,
                        Direction::ExitToClient,
                        &tx_seq,
                        last_ack,
                    )
                    .await?;
                }
                FramePayload::Close => {
                    last_ack = last_ack.max(seq);
                    send_ack(
                        &relay,
                        &session_id,
                        stream_id,
                        Direction::ClientToExit,
                        Direction::ExitToClient,
                        &tx_seq,
                        last_ack,
                    )
                    .await?;
                    let _ = relay.cleanup_acked().await;
                    info!(stream_id, "exit closed stream");
                    return Ok(());
                }
                FramePayload::Reset { reason } => {
                    warn!(stream_id, %reason, "exit reset stream");
                    return Ok(());
                }
                FramePayload::Ack { .. } => {
                    if let Err(error) = relay.cleanup_acked().await {
                        debug!(%error, "client cleanup skipped");
                    }
                }
                FramePayload::Open { .. } | FramePayload::Control(_) => {}
            }
        }
    }
}

pub async fn run_exit(options: ExitOptions) -> Result<()> {
    let allowlist = AllowList::new(options.allow_hosts);
    let budget = ByteBudget::new(options.byte_cap);
    let settings = TransferSettings {
        chunk_size: options.chunk_size,
        data_batch_size: options.data_batch_size,
        batch_flush_interval: options.batch_flush_interval,
        ack_data_frames: options.ack_data_frames,
    };
    let mut streams = HashMap::<u64, ExitStream>::new();
    let mut processed = HashSet::<(u64, u64)>::new();
    let mut ticks = interval(options.relay.poll_interval());
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let deadline = sleep(options.max_runtime);
    tokio::pin!(deadline);

    info!(
        session = %options.relay.session_id(),
        "exit side polling relay"
    );

    loop {
        tokio::select! {
            _ = ticks.tick() => {
                if let Err(error) = process_exit_tick(
                    &options.relay,
                    &allowlist,
                    &budget,
                    settings,
                    &mut streams,
                    &mut processed,
                ).await {
                    warn!(%error, "exit poll failed");
                }
            }
            _ = &mut deadline => {
                info!("exit max runtime reached");
                return Ok(());
            }
        }
    }
}

struct ExitStream {
    writer: OwnedWriteHalf,
    tx_seq: Arc<AtomicU64>,
}

async fn process_exit_tick(
    relay: &GitRelay,
    allowlist: &AllowList,
    budget: &ByteBudget,
    settings: TransferSettings,
    streams: &mut HashMap<u64, ExitStream>,
    processed: &mut HashSet<(u64, u64)>,
) -> Result<()> {
    let session_id = relay.session_id().to_string();
    let frames = relay.read_frames(Some(Direction::ClientToExit)).await?;
    for stored in frames_for_session(frames, &session_id) {
        let stream_id = stored.frame.header.stream_id;
        let seq = stored.frame.header.seq;
        if processed.contains(&(stream_id, seq)) {
            continue;
        }

        let payload = stored.frame.payload;
        match payload {
            FramePayload::Open { host, port } => {
                processed.insert((stream_id, seq));
                if streams.contains_key(&stream_id) {
                    continue;
                }
                if !allowlist.allows(&host, port) {
                    warn!(stream_id, target = %format!("{host}:{port}"), "target denied by allowlist");
                    send_exit_reset(relay, &session_id, stream_id, "target denied").await?;
                    continue;
                }

                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(remote) => {
                        let (reader, writer) = remote.into_split();
                        let tx_seq = Arc::new(AtomicU64::new(1));
                        streams.insert(
                            stream_id,
                            ExitStream {
                                writer,
                                tx_seq: tx_seq.clone(),
                            },
                        );
                        spawn_remote_reader(
                            reader,
                            relay.clone(),
                            session_id.clone(),
                            stream_id,
                            tx_seq.clone(),
                            budget.clone(),
                            settings,
                        );
                        if settings.ack_data_frames {
                            send_ack(
                                relay,
                                &session_id,
                                stream_id,
                                Direction::ExitToClient,
                                Direction::ClientToExit,
                                &tx_seq,
                                seq,
                            )
                            .await?;
                        }
                        info!(stream_id, target = %format!("{host}:{port}"), "opened exit TCP connection");
                    }
                    Err(error) => {
                        warn!(stream_id, target = %format!("{host}:{port}"), %error, "failed to connect exit target");
                        send_exit_reset(relay, &session_id, stream_id, "connect failed").await?;
                    }
                }
            }
            FramePayload::Data { .. } => {
                let Some(stream) = streams.get_mut(&stream_id) else {
                    continue;
                };
                let data = payload.data_bytes()?;
                budget.add(data.len())?;
                stream
                    .writer
                    .write_all(&data)
                    .await
                    .context("failed to write exit socket")?;
                processed.insert((stream_id, seq));
                if settings.ack_data_frames {
                    send_ack(
                        relay,
                        &session_id,
                        stream_id,
                        Direction::ExitToClient,
                        Direction::ClientToExit,
                        &stream.tx_seq,
                        seq,
                    )
                    .await?;
                }
                info!(
                    stream_id,
                    bytes = data.len(),
                    "forwarded client data to exit socket"
                );
            }
            FramePayload::HalfClose => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    stream.writer.shutdown().await.ok();
                    send_ack(
                        relay,
                        &session_id,
                        stream_id,
                        Direction::ExitToClient,
                        Direction::ClientToExit,
                        &stream.tx_seq,
                        seq,
                    )
                    .await?;
                }
                processed.insert((stream_id, seq));
            }
            FramePayload::Close | FramePayload::Reset { .. } => {
                if let Some(stream) = streams.remove(&stream_id) {
                    send_ack(
                        relay,
                        &session_id,
                        stream_id,
                        Direction::ExitToClient,
                        Direction::ClientToExit,
                        &stream.tx_seq,
                        seq,
                    )
                    .await?;
                }
                processed.insert((stream_id, seq));
                info!(stream_id, "client closed stream");
            }
            FramePayload::Ack { .. } => {
                processed.insert((stream_id, seq));
                if let Err(error) = relay.cleanup_acked().await {
                    debug!(%error, "exit cleanup skipped");
                }
            }
            FramePayload::Control(_) => {}
        }
    }
    Ok(())
}

fn spawn_remote_reader(
    mut reader: OwnedReadHalf,
    relay: GitRelay,
    session_id: String,
    stream_id: u64,
    tx_seq: Arc<AtomicU64>,
    budget: ByteBudget,
    settings: TransferSettings,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; settings.chunk_size];
        let mut pending = Vec::<Frame>::new();
        let mut pending_bytes = 0usize;
        loop {
            let read_result = if settings.data_batch_size.is_some() {
                match timeout(settings.batch_flush_interval, reader.read(&mut buf)).await {
                    Ok(result) => Some(result),
                    Err(_) => {
                        if let Err(error) =
                            flush_frame_batch(&relay, &mut pending, &mut pending_bytes).await
                        {
                            warn!(stream_id, %error, "failed to flush exit data batch");
                            return;
                        }
                        None
                    }
                }
            } else {
                Some(reader.read(&mut buf).await)
            };

            let Some(read_result) = read_result else {
                continue;
            };

            match read_result {
                Ok(0) => {
                    if let Err(error) =
                        flush_frame_batch(&relay, &mut pending, &mut pending_bytes).await
                    {
                        warn!(stream_id, %error, "failed to flush exit data batch");
                        return;
                    }
                    if let Err(error) = send_with_next_seq(
                        &relay,
                        &session_id,
                        stream_id,
                        Direction::ExitToClient,
                        &tx_seq,
                        0,
                        FramePayload::Close,
                    )
                    .await
                    {
                        warn!(stream_id, %error, "failed to send exit close frame");
                    }
                    return;
                }
                Ok(n) => {
                    if let Err(error) = budget.add(n) {
                        let _ = send_with_next_seq(
                            &relay,
                            &session_id,
                            stream_id,
                            Direction::ExitToClient,
                            &tx_seq,
                            0,
                            FramePayload::Reset {
                                reason: error.to_string(),
                            },
                        )
                        .await;
                        return;
                    }
                    let frame = next_frame(
                        &session_id,
                        stream_id,
                        Direction::ExitToClient,
                        &tx_seq,
                        0,
                        FramePayload::data(&buf[..n]),
                    );
                    if let Some(batch_size) = settings.data_batch_size {
                        pending_bytes += n;
                        pending.push(frame);
                        if pending_bytes >= batch_size {
                            if let Err(error) =
                                flush_frame_batch(&relay, &mut pending, &mut pending_bytes).await
                            {
                                warn!(stream_id, %error, "failed to send exit data batch");
                                return;
                            }
                        }
                    } else if let Err(error) = relay.write_frame(frame).await {
                        warn!(stream_id, %error, "failed to send exit data frame");
                        return;
                    }
                    info!(stream_id, bytes = n, "sent exit data frame");
                }
                Err(error) => {
                    error!(stream_id, %error, "exit socket read failed");
                    let _ = send_with_next_seq(
                        &relay,
                        &session_id,
                        stream_id,
                        Direction::ExitToClient,
                        &tx_seq,
                        0,
                        FramePayload::Reset {
                            reason: "exit socket read failed".to_string(),
                        },
                    )
                    .await;
                    return;
                }
            }
        }
    });
}

async fn send_exit_reset(
    relay: &GitRelay,
    session_id: &str,
    stream_id: u64,
    reason: &str,
) -> Result<()> {
    let seq = Arc::new(AtomicU64::new(1));
    send_with_next_seq(
        relay,
        session_id,
        stream_id,
        Direction::ExitToClient,
        &seq,
        0,
        FramePayload::Reset {
            reason: reason.to_string(),
        },
    )
    .await
}

async fn send_ack(
    relay: &GitRelay,
    session_id: &str,
    stream_id: u64,
    tx_direction: Direction,
    acked_direction: Direction,
    tx_seq: &Arc<AtomicU64>,
    ack: u64,
) -> Result<()> {
    send_with_next_seq(
        relay,
        session_id,
        stream_id,
        tx_direction,
        tx_seq,
        ack,
        FramePayload::Ack {
            acked_direction,
            ack,
        },
    )
    .await
}

async fn send_with_next_seq(
    relay: &GitRelay,
    session_id: &str,
    stream_id: u64,
    direction: Direction,
    tx_seq: &Arc<AtomicU64>,
    ack: u64,
    payload: FramePayload,
) -> Result<()> {
    relay
        .write_frame(next_frame(
            session_id, stream_id, direction, tx_seq, ack, payload,
        ))
        .await?;
    Ok(())
}

fn next_frame(
    session_id: &str,
    stream_id: u64,
    direction: Direction,
    tx_seq: &Arc<AtomicU64>,
    ack: u64,
    payload: FramePayload,
) -> Frame {
    let seq = tx_seq.fetch_add(1, Ordering::SeqCst);
    Frame::new(
        session_id.to_string(),
        stream_id,
        direction,
        seq,
        ack,
        payload,
    )
}

async fn flush_frame_batch(
    relay: &GitRelay,
    pending: &mut Vec<Frame>,
    pending_bytes: &mut usize,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let frames = std::mem::take(pending);
    *pending_bytes = 0;
    relay.write_frames(frames).await?;
    Ok(())
}

fn frames_for_stream(
    frames: Vec<StoredFrame>,
    session_id: &str,
    stream_id: u64,
) -> impl Iterator<Item = StoredFrame> + '_ {
    frames.into_iter().filter(move |stored| {
        stored.frame.header.session_id == session_id && stored.frame.header.stream_id == stream_id
    })
}

fn frames_for_session(
    frames: Vec<StoredFrame>,
    session_id: &str,
) -> impl Iterator<Item = StoredFrame> + '_ {
    frames
        .into_iter()
        .filter(move |stored| stored.frame.header.session_id == session_id)
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
    fn allowlist_defaults_to_example_only() {
        let allowlist = AllowList::new(Vec::new());
        assert!(allowlist.allows("example.com", 80));
        assert!(allowlist.allows("example.com", 443));
        assert!(!allowlist.allows("127.0.0.1", 8080));
    }

    #[test]
    fn allowlist_accepts_explicit_local_test_port() {
        let allowlist = AllowList::new(vec!["127.0.0.1:8080".to_string()]);
        assert!(allowlist.allows("127.0.0.1", 8080));
        assert!(!allowlist.allows("127.0.0.1", 8081));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_bare_repo_echoes_through_socks() {
        let temp = TempDir::new().unwrap();
        let bare = temp.path().join("scratch.git");
        let init = Command::new("git")
            .args(["init", "--bare", bare.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success());

        let key = TunnelCipher::from_key_bytes([9; 32]);
        let client_relay = GitRelay::new(
            bare.to_string_lossy().to_string(),
            "git-tunnel/e2e".to_string(),
            "session".to_string(),
            Some(temp.path().join("client-work")),
            key.clone(),
            Duration::from_millis(0),
            Duration::from_millis(25),
            false,
        )
        .unwrap();
        let exit_relay = GitRelay::new(
            bare.to_string_lossy().to_string(),
            "git-tunnel/e2e".to_string(),
            "session".to_string(),
            Some(temp.path().join("exit-work")),
            key,
            Duration::from_millis(0),
            Duration::from_millis(25),
            false,
        )
        .unwrap();
        client_relay.ensure_ready().await.unwrap();
        exit_relay.ensure_ready().await.unwrap();

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = client_listener.local_addr().unwrap();
        let client_task = tokio::spawn(run_client_with_listener(
            client_listener,
            ClientOptions {
                relay: client_relay,
                listen: socks_addr,
                chunk_size: 1024,
                data_batch_size: None,
                batch_flush_interval: Duration::from_millis(25),
                ack_data_frames: true,
                byte_cap: 1024 * 1024,
                max_runtime: Duration::from_secs(10),
            },
        ));
        let exit_task = tokio::spawn(run_exit(ExitOptions {
            relay: exit_relay,
            allow_hosts: vec![format!("127.0.0.1:{}", echo_addr.port())],
            chunk_size: 1024,
            data_batch_size: None,
            batch_flush_interval: Duration::from_millis(25),
            ack_data_frames: true,
            byte_cap: 1024 * 1024,
            max_runtime: Duration::from_secs(10),
        }));

        let mut socks = TcpStream::connect(socks_addr).await.unwrap();
        socks.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth = [0u8; 2];
        socks.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [0x05, 0x00]);

        let host = b"127.0.0.1";
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&echo_addr.port().to_be_bytes());
        socks.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        socks.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        socks.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(8), socks.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"ping");

        client_task.abort();
        exit_task.abort();
        echo_task.await.unwrap();
    }
}
