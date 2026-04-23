use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use gittunnel::bench::{run_bench, BenchOptions};
use gittunnel::crypto::TunnelCipher;
use gittunnel::frame::Direction;
use gittunnel::git_relay::{GitRelay, RelayTuning, DEFAULT_MAX_BLOB_BYTES};
use gittunnel::session::Session;
use gittunnel::ssh;
use gittunnel::tunnel::{run_client, run_exit, ClientOptions, ExitOptions};
use tracing_subscriber::EnvFilter;

const DEFAULT_BRANCH: &str = "git-tunnel/session-demo";
const DEFAULT_LISTEN: &str = "127.0.0.1:1080";
const DEFAULT_CHUNK_SIZE: usize = 32 * 1024;
const DEFAULT_PUSH_INTERVAL_MS: u64 = 15_000;
const DEFAULT_POLL_INTERVAL_MS: u64 = 15_000;
const DEFAULT_BYTE_CAP: u64 = 8 * 1024 * 1024;
const DEFAULT_MAX_RUNTIME_SECS: u64 = 30 * 60;
const GITHUB_BULK_PUSH_INTERVAL_MS: u64 = 20_000;
const GITHUB_BULK_BENCH_PUSH_INTERVAL_MS: u64 = 10_000;
const GITHUB_BULK_POLL_INTERVAL_MS: u64 = 1_000;
const GITHUB_BULK_CHUNK_SIZE: usize = 64 * 1024;
const GITHUB_BULK_BATCH_SIZE: usize = 512 * 1024;
const DEFAULT_BATCH_FLUSH_INTERVAL_MS: u64 = 250;

#[derive(Debug, Parser)]
#[command(name = "gittunnel")]
#[command(about = "A deliberately slow TCP-over-GitHub push/fetch SOCKS5 demo.")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long, global = true, default_value = "info", env = "RUST_LOG")]
    log: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the local SOCKS5 listener and send traffic into the Git relay.
    Client(ClientArgs),
    /// Run the remote TCP exit side and forward relay frames to real sockets.
    Exit(ExitArgs),
    /// Measure one-way GitHub relay bulk throughput and latency honestly.
    Bench(BenchArgs),
    /// Delete the relay branch and remove the local relay cache.
    Clean(CleanArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RuntimeProfile {
    Conservative,
    GithubBulk,
    GithubMulti,
}

impl RuntimeProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::GithubBulk => "github-bulk",
            Self::GithubMulti => "github-multi",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Protocol {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BenchMode {
    OneWay,
}

#[derive(Debug, Args, Clone)]
struct RelayArgs {
    /// GitHub repository URL used as the relay.
    #[arg(long)]
    repo: String,

    /// Scratch branch used for relay frames.
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,

    /// Shared encryption key file. Accepts 32 raw bytes, hex, or base64.
    #[arg(long)]
    key: PathBuf,

    /// Optional session id. Defaults to a stable id derived from branch.
    #[arg(long)]
    session: Option<String>,

    /// Directory for the internal Git working copy.
    #[arg(long)]
    workdir: Option<PathBuf>,

    /// Print frame metadata in logs. Payloads are never logged.
    #[arg(long)]
    trace_frames: bool,

    /// Minimum delay between pushes from this process.
    #[arg(long, default_value_t = DEFAULT_PUSH_INTERVAL_MS)]
    push_interval_ms: u64,

    /// Delay between relay fetches.
    #[arg(long, default_value_t = DEFAULT_POLL_INTERVAL_MS)]
    poll_interval_ms: u64,

    /// Runtime tuning profile. github-bulk uses split branches and deferred cleanup.
    #[arg(long, value_enum, default_value_t = RuntimeProfile::Conservative)]
    profile: RuntimeProfile,

    /// Tunnel protocol version. v1 keeps the legacy relay; v2 uses branch-per-stream refs.
    #[arg(long, value_enum, default_value_t = Protocol::V1)]
    protocol: Protocol,
}

#[derive(Debug, Args, Clone)]
struct ClientArgs {
    #[command(flatten)]
    relay: RelayArgs,

    /// SOCKS5 listen address. Defaults to loopback only.
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,

    /// Maximum plaintext payload bytes per tunnel data frame.
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: usize,

    /// Maximum plaintext payload accumulated into one Git batch push.
    #[arg(long)]
    batch_size: Option<usize>,

    /// Maximum time to hold a partial data batch before pushing it.
    #[arg(long, default_value_t = DEFAULT_BATCH_FLUSH_INTERVAL_MS)]
    batch_flush_interval_ms: u64,

    /// Pre-created branch-pair slots for github-multi. Use 0 for cold branches.
    #[arg(long, default_value_t = 4)]
    warm_pool_size: usize,

    /// Maximum bytes this process will relay before exiting.
    #[arg(long, default_value_t = DEFAULT_BYTE_CAP)]
    byte_cap: u64,

    /// Maximum runtime in seconds.
    #[arg(long, default_value_t = DEFAULT_MAX_RUNTIME_SECS)]
    max_runtime_secs: u64,

    /// Required to lift conservative demo byte/runtime caps.
    #[arg(long)]
    i_understand_this_is_a_demo: bool,
}

#[derive(Debug, Args, Clone)]
struct ExitArgs {
    #[command(flatten)]
    relay: RelayArgs,

    /// Allowed outbound target pattern, such as example.com:80 or 127.0.0.1:*.
    #[arg(long = "allow-host")]
    allow_hosts: Vec<String>,

    /// Maximum plaintext payload bytes per tunnel data frame.
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: usize,

    /// Maximum plaintext payload accumulated into one Git batch push.
    #[arg(long)]
    batch_size: Option<usize>,

    /// Maximum time to hold a partial data batch before pushing it.
    #[arg(long, default_value_t = DEFAULT_BATCH_FLUSH_INTERVAL_MS)]
    batch_flush_interval_ms: u64,

    /// Maximum bytes this process will relay before exiting.
    #[arg(long, default_value_t = DEFAULT_BYTE_CAP)]
    byte_cap: u64,

    /// Maximum runtime in seconds.
    #[arg(long, default_value_t = DEFAULT_MAX_RUNTIME_SECS)]
    max_runtime_secs: u64,

    /// Required to lift conservative demo byte/runtime caps.
    #[arg(long)]
    i_understand_this_is_a_demo: bool,
}

#[derive(Debug, Args, Clone)]
struct BenchArgs {
    #[command(flatten)]
    relay: RelayArgs,

    /// Benchmark mode. Only one-way relay mode is supported.
    #[arg(long, value_enum, default_value_t = BenchMode::OneWay)]
    mode: BenchMode,

    /// Target payload throughput for reporting.
    #[arg(long, default_value_t = 50.0)]
    target_kib_s: f64,

    /// Latency target retained for honest met/unmet reporting.
    #[arg(long, default_value_t = 300)]
    latency_target_ms: u64,

    /// Total plaintext payload bytes to send through the relay.
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    bytes: usize,

    /// Plaintext data bytes per tunnel frame inside each batch.
    #[arg(long, default_value_t = GITHUB_BULK_CHUNK_SIZE)]
    chunk_size: usize,

    /// Plaintext payload bytes per Git batch push.
    #[arg(long, default_value_t = GITHUB_BULK_BATCH_SIZE)]
    batch_size: usize,
}

#[derive(Debug, Args, Clone)]
struct CleanArgs {
    /// GitHub repository URL used as the relay.
    #[arg(long)]
    repo: String,

    /// Scratch branch to delete.
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,

    /// Directory for the internal Git working copy.
    #[arg(long)]
    workdir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log)?;

    match cli.command {
        Command::Client(args) => {
            validate_demo_caps(
                args.byte_cap,
                args.max_runtime_secs,
                args.i_understand_this_is_a_demo,
            )?;
            if !args.listen.ip().is_loopback() {
                bail!("client listener must be loopback for this demo");
            }
            let cipher = TunnelCipher::from_key_file(&args.relay.key)?;
            log_profile(args.relay.profile, false);
            if args.relay.profile == RuntimeProfile::GithubMulti {
                let session_id = args
                    .relay
                    .session
                    .clone()
                    .unwrap_or_else(|| GitRelay::session_from_branch(&args.relay.branch));
                let ssh_env = ssh::is_ssh_remote(&args.relay.repo)
                    .then(|| ssh::ssh_env_for_control_dir(&ssh::control_dir()));
                std::fs::create_dir_all(ssh::control_dir()).ok();
                let session = Arc::new(Session::new(
                    &args.relay.repo,
                    &session_id,
                    Arc::new(cipher),
                    ssh_env,
                ));
                session
                    .run_client(
                        args.listen,
                        args.byte_cap,
                        Duration::from_secs(args.max_runtime_secs),
                        args.warm_pool_size,
                    )
                    .await
            } else {
                validate_chunk_size(args.chunk_size)?;
                let data_batch_size = effective_batch_size(args.relay.profile, args.batch_size)?;
                let relay =
                    build_relay(&args.relay, cipher, Direction::ClientToExit, false).await?;
                run_client(ClientOptions {
                    relay,
                    listen: args.listen,
                    chunk_size: args.chunk_size,
                    data_batch_size,
                    batch_flush_interval: Duration::from_millis(args.batch_flush_interval_ms),
                    ack_data_frames: args.relay.profile != RuntimeProfile::GithubBulk,
                    byte_cap: args.byte_cap,
                    max_runtime: Duration::from_secs(args.max_runtime_secs),
                })
                .await
            }
        }
        Command::Exit(args) => {
            validate_demo_caps(
                args.byte_cap,
                args.max_runtime_secs,
                args.i_understand_this_is_a_demo,
            )?;
            let cipher = TunnelCipher::from_key_file(&args.relay.key)?;
            log_profile(args.relay.profile, false);
            if args.relay.profile == RuntimeProfile::GithubMulti {
                let session_id = args
                    .relay
                    .session
                    .clone()
                    .unwrap_or_else(|| GitRelay::session_from_branch(&args.relay.branch));
                let ssh_env = ssh::is_ssh_remote(&args.relay.repo)
                    .then(|| ssh::ssh_env_for_control_dir(&ssh::control_dir()));
                std::fs::create_dir_all(ssh::control_dir()).ok();
                let session = Arc::new(Session::new(
                    &args.relay.repo,
                    &session_id,
                    Arc::new(cipher),
                    ssh_env,
                ));
                session
                    .run_exit(
                        args.allow_hosts,
                        args.byte_cap,
                        Duration::from_secs(args.max_runtime_secs),
                    )
                    .await
            } else {
                validate_chunk_size(args.chunk_size)?;
                let data_batch_size = effective_batch_size(args.relay.profile, args.batch_size)?;
                let relay =
                    build_relay(&args.relay, cipher, Direction::ExitToClient, false).await?;
                run_exit(ExitOptions {
                    relay,
                    allow_hosts: args.allow_hosts,
                    chunk_size: args.chunk_size,
                    data_batch_size,
                    batch_flush_interval: Duration::from_millis(args.batch_flush_interval_ms),
                    ack_data_frames: args.relay.profile != RuntimeProfile::GithubBulk,
                    byte_cap: args.byte_cap,
                    max_runtime: Duration::from_secs(args.max_runtime_secs),
                })
                .await
            }
        }
        Command::Bench(args) => {
            if args.mode != BenchMode::OneWay {
                bail!("only one-way benchmark mode is supported");
            }
            validate_chunk_size(args.chunk_size)?;
            validate_batch_size(args.batch_size)?;
            let cipher = TunnelCipher::from_key_file(&args.relay.key)?;
            let session_id = args
                .relay
                .session
                .clone()
                .unwrap_or_else(|| GitRelay::session_from_branch(&args.relay.branch));
            log_profile(RuntimeProfile::GithubBulk, true);
            run_bench(BenchOptions {
                repo: args.relay.repo,
                branch: args.relay.branch,
                session_id,
                workdir: args.relay.workdir,
                cipher,
                trace_frames: args.relay.trace_frames,
                push_interval: Duration::from_millis(effective_push_interval_ms(
                    RuntimeProfile::GithubBulk,
                    args.relay.push_interval_ms,
                    true,
                )),
                poll_interval: Duration::from_millis(effective_poll_interval_ms(
                    RuntimeProfile::GithubBulk,
                    args.relay.poll_interval_ms,
                )),
                target_kib_s: args.target_kib_s,
                latency_target: Duration::from_millis(args.latency_target_ms),
                total_bytes: args.bytes,
                chunk_size: args.chunk_size,
                batch_size: args.batch_size,
                max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
            })
            .await
        }
        Command::Clean(args) => {
            let relay = GitRelay::without_cipher(
                args.repo,
                args.branch,
                args.workdir,
                Duration::from_millis(DEFAULT_PUSH_INTERVAL_MS),
                Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
                false,
            )?;
            relay.clean().await
        }
    }
}

async fn build_relay(
    args: &RelayArgs,
    cipher: TunnelCipher,
    write_direction: Direction,
    one_way_bench: bool,
) -> Result<GitRelay> {
    let session_id = args
        .session
        .clone()
        .unwrap_or_else(|| GitRelay::session_from_branch(&args.branch));
    let push_interval = Duration::from_millis(effective_push_interval_ms(
        args.profile,
        args.push_interval_ms,
        one_way_bench,
    ));
    let poll_interval = Duration::from_millis(effective_poll_interval_ms(
        args.profile,
        args.poll_interval_ms,
    ));
    let relay = if args.profile == RuntimeProfile::GithubBulk {
        GitRelay::new_split(
            args.repo.clone(),
            args.branch.clone(),
            write_direction,
            session_id,
            args.workdir.clone(),
            cipher,
            RelayTuning::new(
                push_interval,
                poll_interval,
                args.trace_frames,
                true,
                DEFAULT_MAX_BLOB_BYTES,
            ),
        )?
    } else {
        GitRelay::new(
            args.repo.clone(),
            args.branch.clone(),
            session_id,
            args.workdir.clone(),
            cipher,
            push_interval,
            poll_interval,
            args.trace_frames,
        )?
    };
    relay.ensure_ready().await?;
    Ok(relay)
}

fn log_profile(profile: RuntimeProfile, one_way_bench: bool) {
    tracing::info!(
        profile = profile.as_str(),
        one_way_bench,
        "GitHub-only relay demo profile active; latency is measured honestly and not hidden"
    );
}

fn init_logging(filter: &str) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter).context("invalid log filter")?)
        .with_target(false)
        .init();
    Ok(())
}

fn validate_chunk_size(chunk_size: usize) -> Result<()> {
    if chunk_size == 0 || chunk_size > 64 * 1024 {
        bail!("chunk size must be between 1 and 65536 bytes");
    }
    Ok(())
}

fn validate_batch_size(batch_size: usize) -> Result<()> {
    if batch_size == 0 || batch_size > GITHUB_BULK_BATCH_SIZE {
        bail!(
            "batch size must be between 1 and {} bytes for github-bulk",
            GITHUB_BULK_BATCH_SIZE
        );
    }
    Ok(())
}

fn effective_batch_size(
    profile: RuntimeProfile,
    requested: Option<usize>,
) -> Result<Option<usize>> {
    match profile {
        RuntimeProfile::Conservative => {
            if let Some(batch_size) = requested {
                validate_batch_size(batch_size)?;
                Ok(Some(batch_size))
            } else {
                Ok(None)
            }
        }
        RuntimeProfile::GithubBulk | RuntimeProfile::GithubMulti => {
            let batch_size = requested.unwrap_or(GITHUB_BULK_BATCH_SIZE);
            validate_batch_size(batch_size)?;
            Ok(Some(batch_size))
        }
    }
}

fn effective_push_interval_ms(
    profile: RuntimeProfile,
    requested_ms: u64,
    one_way_bench: bool,
) -> u64 {
    match profile {
        RuntimeProfile::Conservative => requested_ms,
        RuntimeProfile::GithubBulk | RuntimeProfile::GithubMulti => {
            let minimum = if one_way_bench {
                GITHUB_BULK_BENCH_PUSH_INTERVAL_MS
            } else {
                GITHUB_BULK_PUSH_INTERVAL_MS
            };
            if one_way_bench && requested_ms == DEFAULT_PUSH_INTERVAL_MS {
                minimum
            } else {
                requested_ms.max(minimum)
            }
        }
    }
}

fn effective_poll_interval_ms(profile: RuntimeProfile, requested_ms: u64) -> u64 {
    match profile {
        RuntimeProfile::Conservative => requested_ms,
        RuntimeProfile::GithubBulk | RuntimeProfile::GithubMulti
            if requested_ms == DEFAULT_POLL_INTERVAL_MS =>
        {
            GITHUB_BULK_POLL_INTERVAL_MS
        }
        RuntimeProfile::GithubBulk | RuntimeProfile::GithubMulti => {
            requested_ms.max(GITHUB_BULK_POLL_INTERVAL_MS)
        }
    }
}

fn validate_demo_caps(byte_cap: u64, max_runtime_secs: u64, override_caps: bool) -> Result<()> {
    if override_caps {
        return Ok(());
    }
    if byte_cap > DEFAULT_BYTE_CAP {
        bail!("byte cap exceeds the conservative demo default; pass --i-understand-this-is-a-demo to override");
    }
    if max_runtime_secs > DEFAULT_MAX_RUNTIME_SECS {
        bail!("runtime cap exceeds the conservative demo default; pass --i-understand-this-is-a-demo to override");
    }
    Ok(())
}
